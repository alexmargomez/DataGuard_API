import base64
import hashlib
import threading
import time
from collections import OrderedDict
from typing import Optional, Tuple

from app.domain.ports.vault_port import TokenVaultPort


class InMemoryTtlVaultAdapter(TokenVaultPort):
    """
    Adaptador de Infraestructura de Bóveda con:
      1. Sincronización multihilo (threading.RLock) contra carreras concurrentes en ASGI.
      2. Evicción perezosa O(1) amortizada desde la cabeza del OrderedDict (sin barridos O(N) completos en cada store).
      3. Cifrado simétrico en reposo (keystream SHA-256) para no mantener PII en texto claro en el heap de Python.
    """

    def __init__(
        self,
        max_capacity: int = 5000,
        ttl_seconds: float = 3600.0,
        encryption_secret: str = "dataguard_ley1581_vault_heap_key",
    ) -> None:
        self._max_capacity = max(1, max_capacity)
        self._ttl_seconds = max(0.01, ttl_seconds)
        self._key_digest = hashlib.sha256(encryption_secret.encode("utf-8")).digest()
        self._lock = threading.RLock()
        self._entries: "OrderedDict[str, Tuple[float, str]]" = OrderedDict()

    def _cipher_transform(self, token: str, data_bytes: bytes) -> bytes:
        stream_seed = hashlib.sha256(self._key_digest + token.encode("utf-8")).digest()
        out = bytearray(len(data_bytes))
        for idx, b in enumerate(data_bytes):
            if idx > 0 and idx % 32 == 0:
                stream_seed = hashlib.sha256(stream_seed).digest()
            out[idx] = b ^ stream_seed[idx % 32]
        return bytes(out)

    def _encrypt(self, token: str, raw_value: str) -> str:
        encrypted = self._cipher_transform(token, raw_value.encode("utf-8"))
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def _decrypt(self, token: str, ciphertext_b64: str) -> str:
        encrypted = base64.urlsafe_b64decode(ciphertext_b64.encode("ascii"))
        decrypted = self._cipher_transform(token, encrypted)
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
        ciphertext = self._encrypt(token, raw_value)
        with self._lock:
            self._evict_expired_head_locked(now)
            if token in self._entries:
                self._entries.move_to_end(token)
            elif len(self._entries) >= self._max_capacity:
                self._entries.popitem(last=False)
            self._entries[token] = (now + self._ttl_seconds, ciphertext)

    def resolve(self, token: str) -> Optional[str]:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return None
            expires_at, ciphertext = entry
            if now >= expires_at:
                self._entries.pop(token, None)
                return None
            self._entries.move_to_end(token)
            return self._decrypt(token, ciphertext)

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
