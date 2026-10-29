from abc import ABC, abstractmethod
from typing import Optional


class TokenVaultPort(ABC):
    """Puerto de Salida Puro (Hexagonal Architecture) para la Bóveda de Tokens Reversibles."""

    @abstractmethod
    def store(self, token: str, raw_value: str) -> None:
        pass

    @abstractmethod
    def resolve(self, token: str) -> Optional[str]:
        pass

    @abstractmethod
    def size(self) -> int:
        pass


from app.infrastructure.persistence.in_memory_vault_adapter import InMemoryTtlVaultAdapter  # noqa: E402

__all__ = ["TokenVaultPort", "InMemoryTtlVaultAdapter"]
