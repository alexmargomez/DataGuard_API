import base64
import hashlib
import hmac
import os
import threading
import time
from collections import OrderedDict
from typing import Optional, Tuple

from app.domain.ports.vault_port import TokenVaultPort


class InMemoryTtlVaultAdapter(TokenVaultPort):
    """
    Adaptador de Infraestructura de Bóveda con:
      1. Sincronización multihilo (threading.RLock) con cifrado/descifrado ejecutado FUERA de la sección crítica.
      2. Evicción perezosa O(1) amortizada desde la cabeza del OrderedDict.
      3. Cifrado autenticado en reposo (Nonce aleatorio de 16 bytes + Keystream SHA-256 + Etiqueta Encrypt-then-MAC HMAC-SHA256)
         para no mantener PII en texto claro en el heap de Python y detectar cualquier alteración de memoria.
    """

    def __init__(
        self,
        max_capacity: int = 5000,
        ttl_seconds: float = 3600.0,
        encryption_secret: str = "dataguard_ley1581_vault_heap_key",
    ) -> None:
        self._max_capacity = max(1, max_capacity)
        self._ttl_seconds = max(0.01, ttl_seconds)
        self._enc_key = hashlib.sha256((encryption_secret + ":enc").encode("utf-8")).digest()
        self._mac_key = hashlib.sha256((encryption_secret + ":mac").encode("utf-8")).digest()
        self._lock = threading.RLock()
        self._entries: "OrderedDict[str, Tuple[float, str]]" = OrderedDict()

    def _cipher_transform(self, nonce: bytes, token: str, data_bytes: bytes) -> bytes:
        stream_seed = hashlib.sha256(self._enc_key + nonce + token.encode("utf-8")).digest()
        out = bytearray(len(data_bytes))
        for idx, b in enumerate(data_bytes):
            if idx > 0 and idx % 32 == 0:
                stream_seed = hashlib.sha256(stream_seed + nonce).digest()
            out[idx] = b ^ stream_seed[idx % 32]
        return bytes(out)

    def _encrypt(self, token: str, raw_value: str) -> str:
        nonce = os.urandom(16)
        ciphertext = self._cipher_transform(nonce, token, raw_value.encode("utf-8"))
        payload = nonce + ciphertext
        mac = hmac.new(self._mac_key, token.encode("utf-8") + payload, hashlib.sha256).hexdigest()
        b64_payload = base64.urlsafe_b64encode(payload).decode("ascii")
        return f"{b64_payload}.{mac}"

    def _decrypt(self, token: str, envelope: str) -> Optional[str]:
        if "." not in envelope:
            return None
        b64_payload, mac_hex = envelope.split(".", 1)
        payload = base64.urlsafe_b64decode(b64_payload.encode("ascii"))
        expected_mac = hmac.new(self._mac_key, token.encode("utf-8") + payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac_hex, expected_mac):
            raise ValueError("Integridad criptográfica de bóveda violada (MAC inválido).")
        nonce, ciphertext = payload[:16], payload[16:]
        decrypted = self._cipher_transform(nonce, token, ciphertext)
        return decrypted.decode("utf-8")

    def _evict_expired_head_locked(self, now: float) -> None:
        while self._entries:
            oldest_key, (expires_at, _) = next(iter(self._entries.items()))
            if now >= expires_at:
                self._entries.pop(oldest_key, None)
            else:
                break

    def store(self, token: str, raw_value: str) -> None:
        now = time.monotonic()
        # Cifrado y firma HMAC ejecutados FUERA del RLock para minimizar contención entre hilos
        envelope = self._encrypt(token, raw_value)
        with self._lock:
            self._evict_expired_head_locked(now)
            if token in self._entries:
                self._entries.move_to_end(token)
            elif len(self._entries) >= self._max_capacity:
                self._entries.popitem(last=False)
            self._entries[token] = (now + self._ttl_seconds, envelope)

    def resolve(self, token: str) -> Optional[str]:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return None
            expires_at, envelope = entry
            if now >= expires_at:
                self._entries.pop(token, None)
                return None
            self._entries.move_to_end(token)
        # Descifrado y verificación de MAC ejecutados FUERA del RLock
        return self._decrypt(token, envelope)

    def size(self) -> int:
        now = time.monotonic()
        with self._lock:
            expired_keys = [
                k for k, (expires_at, _) in self._entries.items() if now >= expires_at
            ]
            for k in expired_keys:
                self._entries.pop(k, None)
            return len(self._entries)

    def __setitem__(self, key: str, value: str) -> None:
        self.store(key, value)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        val = self.resolve(key)
        return val if val is not None else default

    def __len__(self) -> int:
        return self.size()
