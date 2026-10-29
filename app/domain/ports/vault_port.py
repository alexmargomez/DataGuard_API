import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Dict, Optional, Tuple


class TokenVaultPort(ABC):
    """Puerto de Salida (Hexagonal Architecture) para la Bóveda de Tokens Reversibles."""

    @abstractmethod
    def store(self, token: str, raw_value: str) -> None:
        pass

    @abstractmethod
    def resolve(self, token: str) -> Optional[str]:
        pass

    @abstractmethod
    def size(self) -> int:
        pass


class InMemoryTtlVaultAdapter(TokenVaultPort):
    """
    Adaptador de Bóveda en Memoria con Expiración Temporal (TTL) y Evicción LRU Acotada.
    Garantiza que los datos sensibles bajo Ley 1581 no permanezcan indefinidamente en RAM.
    """

    def __init__(self, max_capacity: int = 5000, ttl_seconds: float = 3600.0) -> None:
        self._max_capacity = max(1, max_capacity)
        self._ttl_seconds = max(0.01, ttl_seconds)
        self._entries: "OrderedDict[str, Tuple[float, str]]" = OrderedDict()

    def _purge_expired(self, now: float) -> None:
        expired_keys = [
            k for k, (expires_at, _) in self._entries.items() if now >= expires_at
        ]
        for k in expired_keys:
            self._entries.pop(k, None)

    def store(self, token: str, raw_value: str) -> None:
        now = time.monotonic()
        self._purge_expired(now)
        if token in self._entries:
            self._entries.move_to_end(token)
        elif len(self._entries) >= self._max_capacity:
            self._entries.popitem(last=False)
        self._entries[token] = (now + self._ttl_seconds, raw_value)

    def resolve(self, token: str) -> Optional[str]:
        now = time.monotonic()
        entry = self._entries.get(token)
        if entry is None:
            return None
        expires_at, raw_value = entry
        if now >= expires_at:
            self._entries.pop(token, None)
            return None
        self._entries.move_to_end(token)
        return raw_value

    def size(self) -> int:
        self._purge_expired(time.monotonic())
        return len(self._entries)

    def __setitem__(self, key: str, value: str) -> None:
        self.store(key, value)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        val = self.resolve(key)
        return val if val is not None else default

    def __len__(self) -> int:
        return self.size()
