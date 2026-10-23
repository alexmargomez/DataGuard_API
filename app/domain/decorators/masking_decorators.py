import hashlib
import hmac
import os
from abc import ABC, abstractmethod
from typing import Dict


class MaskingComponent(ABC):
    """Componente base del patrón Decorator para estrategias de anonimización (Ley 1581 Habeas Data)."""

    @abstractmethod
    def mask(self, category: str, raw_value: str) -> str:
        pass


class BaseRawMasker(MaskingComponent):
    def mask(self, category: str, raw_value: str) -> str:
        return raw_value


class MaskingStrategyDecorator(MaskingComponent):
    def __init__(self, wrapped: MaskingComponent) -> None:
        self._wrapped = wrapped


class RedactionMaskDecorator(MaskingStrategyDecorator):
    """Enmascara parcialmente el dato sensible preservando prefijo/sufijo mínimo de referencia."""

    def mask(self, category: str, raw_value: str) -> str:
        val = self._wrapped.mask(category, raw_value).strip()
        if category == "EMAIL" and "@" in val:
            user, domain = val.split("@", 1)
            prefix = user[:2] if len(user) >= 2 else user[:1]
            return f"{prefix}***@{domain}"
        if len(val) <= 4:
            return "****"
        return f"{val[:3]}{'*' * (len(val) - 5)}{val[-2:]}"


class DeterministicHmacDecorator(MaskingStrategyDecorator):
    """
    Genera un pseudónimo determinístico (HMAC-SHA256) que conserva la integridad referencial
    en bases de datos de prueba sin revelar el dato real.
    """

    def __init__(self, wrapped: MaskingComponent, secret: str) -> None:
        super().__init__(wrapped)
        self._secret = secret.encode("utf-8")

    def mask(self, category: str, raw_value: str) -> str:
        val = self._wrapped.mask(category, raw_value).strip()
        digest = hmac.new(self._secret, val.encode("utf-8"), hashlib.sha256).hexdigest()[:10].upper()
        return f"TKN_{category}_{digest}"


class ReversibleVaultDecorator(MaskingStrategyDecorator):
    """
    Almacena el valor en una bóveda en memoria indexada por token criptográfico
    para permitir reversión autorizada con llave maestra.
    """

    def __init__(self, wrapped: MaskingComponent, secret: str, vault_store: Dict[str, str]) -> None:
        super().__init__(wrapped)
        self._secret = secret.encode("utf-8")
        self._vault = vault_store

    def mask(self, category: str, raw_value: str) -> str:
        val = self._wrapped.mask(category, raw_value).strip()
        digest = hmac.new(self._secret, f"VAULT:{category}:{val}".encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        token = f"VLT_{category}_{digest}"
        self._vault[token] = val
        return token


def build_masker(mode: str, secret: str, vault_store: Dict[str, str]) -> MaskingComponent:
    base = BaseRawMasker()
    normalized = (mode or "REDACT").strip().upper()
    if normalized == "DETERMINISTIC_TOKEN":
        return DeterministicHmacDecorator(base, secret)
    if normalized == "REVERSIBLE_VAULT":
        return ReversibleVaultDecorator(base, secret, vault_store)
    return RedactionMaskDecorator(base)
