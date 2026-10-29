from typing import Any, Dict, List, Optional
from app.domain.decorators.masking_decorators import build_masker
from app.domain.ports.vault_port import InMemoryTtlVaultAdapter, TokenVaultPort
from app.domain.visitor.json_masking_visitor import JsonTreeMaskingVisitor


class PrivacyMaskingUseCase:
    """Caso de Uso de Aplicación que orquesta anonimización JSON/Texto y destokenización segura."""

    def __init__(self, vault_secret: str, vault_port: Optional[TokenVaultPort] = None) -> None:
        self._secret = vault_secret
        self._vault: Any = vault_port if vault_port is not None else InMemoryTtlVaultAdapter()

    @property
    def vault_size(self) -> int:
        return self._vault.size()

    def mask_json(self, mode: str, payload: Any) -> Dict[str, Any]:
        masker = build_masker(mode, self._secret, self._vault)
        visitor = JsonTreeMaskingVisitor(masker)
        sanitized = visitor.visit(payload)
        return {
            "complianceStandard": "Ley 1581 de 2012 (Habeas Data Colombia) / HIPAA Safe Harbor",
            "strategyApplied": (mode or "REDACT").upper(),
            "totalPiiDetected": len(visitor.findings),
            "sanitizedPayload": sanitized,
            "auditFindings": visitor.findings,
        }

    def mask_text(self, mode: str, text: str) -> Dict[str, Any]:
        masker = build_masker(mode, self._secret, self._vault)
        visitor = JsonTreeMaskingVisitor(masker)
        sanitized_text = visitor.visit_string(text)
        return {
            "strategyApplied": (mode or "REDACT").upper(),
            "totalPiiDetected": len(visitor.findings),
            "sanitizedText": sanitized_text,
            "auditFindings": visitor.findings,
        }

    def unmask_tokens(self, tokens: List[str]) -> Dict[str, Any]:
        resolved: Dict[str, Optional[str]] = {}
        for tkn in tokens:
            resolved[tkn] = self._vault.resolve(tkn)
        return {
            "requestedCount": len(tokens),
            "resolved": resolved,
        }
