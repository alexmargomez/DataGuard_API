import re
from typing import Any, Dict, List
from app.domain.decorators.masking_decorators import MaskingComponent


def is_valid_luhn(card_digits: str) -> bool:
    """Verifica matemáticamente si una secuencia de 13-19 dígitos cumple el Algoritmo de Luhn (ISO/IEC 7812)."""
    digits = [int(d) for d in card_digits if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class JsonTreeMaskingVisitor:
    """
    Visitor Pattern — Recorre recursivamente estructuras JSON arbitrarias (dict, list, str)
    con protección contra desbordamiento de pila (MAX_RECURSION_DEPTH = 32),
    detectando y anonimizando datos personales y clínicos sensibles (Ley 1581 Habeas Data / HIPAA).
    """

    MAX_RECURSION_DEPTH = 32

    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    CO_MOBILE_RE = re.compile(r"\b(?:\+57[\s-]?)?3\d{2}[\s-]?\d{3}[\s-]?\d{4}\b")
    CREDIT_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    CO_NIT_RE = re.compile(r"\b(?:8|9)\d{2}\.?\d{3}\.?\d{3}-\d\b")
    # Evita falsos positivos con valores monetarios precedidos por $ o COP
    CO_CEDULA_RE = re.compile(r"(?<![$\w])(?:1\d{9}|[1-9]\d{6,7})\b")

    SENSITIVE_KEY_HINTS = {
        "cedula": "DOC_ID",
        "documento": "DOC_ID",
        "identificacion": "DOC_ID",
        "nit": "NIT_CO",
        "telefono": "PHONE_CO",
        "celular": "PHONE_CO",
        "phone": "PHONE_CO",
        "email": "EMAIL",
        "correo": "EMAIL",
        "tarjeta": "CREDIT_CARD",
        "card": "CREDIT_CARD",
        "historia_clinica": "CLINICAL_RECORD",
    }

    def __init__(self, masker: MaskingComponent, max_depth: int = MAX_RECURSION_DEPTH) -> None:
        self._masker = masker
        self._max_depth = max_depth
        self.findings: List[Dict[str, str]] = []

    def visit(self, node: Any, path: str = "$", depth: int = 0) -> Any:
        if depth > self._max_depth:
            raise ValueError(
                f"Profundidad máxima de anidamiento JSON excedida ({self._max_depth} niveles) en '{path}'."
            )
        if isinstance(node, dict):
            return self._visit_dict(node, path, depth + 1)
        if isinstance(node, list):
            return [self.visit(item, f"{path}[{idx}]", depth + 1) for idx, item in enumerate(node)]
        if isinstance(node, str):
            return self.visit_string(node, path)
        return node

    def _visit_dict(self, data: Dict[str, Any], path: str, depth: int) -> Dict[str, Any]:
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            current_path = f"{path}.{k}"
            lower_key = k.lower().strip()
            matched_category = None
            for hint, cat in self.SENSITIVE_KEY_HINTS.items():
                if hint in lower_key:
                    matched_category = cat
                    break

            if matched_category and isinstance(v, (str, int)) and str(v).strip():
                raw_str = str(v)
                masked_val = self._masker.mask(matched_category, raw_str)
                self._record_finding(current_path, matched_category, raw_str, masked_val)
                sanitized[k] = masked_val
            else:
                sanitized[k] = self.visit(v, current_path, depth)
        return sanitized

    EXISTING_TOKEN_RE = re.compile(r"\b(?:VLT|HASH)_[A-Z_]+_[0-9a-fA-F]+\b|\[REDACTED:[^\]]+\]")

    def visit_string(self, text: str, path: str = "$.text") -> str:
        placeholders: List[str] = []

        def store_placeholder(masked_token: str) -> str:
            idx = len(placeholders)
            placeholders.append(masked_token)
            return f"\x00DG_TOKEN_{idx}\x00"

        # Proteger tokens previamente generados para evitar re-tokenización
        result = self.EXISTING_TOKEN_RE.sub(lambda m: store_placeholder(m.group(0)), text)

        # 1. Tarjetas de Crédito con verificación matemática de Luhn
        for match in list(self.CREDIT_CARD_CANDIDATE_RE.finditer(result)):
            candidate = match.group(0)
            clean_digits = re.sub(r"\D", "", candidate)
            if is_valid_luhn(clean_digits):
                masked = self._masker.mask("CREDIT_CARD", clean_digits)
                self._record_finding(path, "CREDIT_CARD", candidate, masked)
                result = result.replace(candidate, store_placeholder(masked), 1)

        # 2. Correos electrónicos
        result = self._replace_pattern(result, self.EMAIL_RE, "EMAIL", path, store_placeholder)

        # 3. Teléfonos celulares colombianos (+57 3xx xxx xxxx)
        result = self._replace_pattern(result, self.CO_MOBILE_RE, "PHONE_CO", path, store_placeholder)

        # 4. NITs colombianos con formato (8xx.xxx.xxx-x / 9xx.xxx.xxx-x)
        result = self._replace_pattern(result, self.CO_NIT_RE, "NIT_CO", path, store_placeholder)

        # 5. Cédulas de ciudadanía en texto libre (excluyendo montos precedidos por $)
        result = self._replace_pattern(result, self.CO_CEDULA_RE, "DOC_ID", path, store_placeholder)

        for idx, token_val in enumerate(placeholders):
            result = result.replace(f"\x00DG_TOKEN_{idx}\x00", token_val)

        return result

    def _replace_pattern(
        self,
        text: str,
        pattern: re.Pattern,
        category: str,
        path: str,
        wrap_token=None,
    ) -> str:
        def repl(match: re.Match) -> str:
            orig = match.group(0)
            masked = self._masker.mask(category, orig)
            self._record_finding(path, category, orig, masked)
            return wrap_token(masked) if wrap_token else masked

        return pattern.sub(repl, text)

    def _record_finding(self, json_path: str, category: str, original: str, masked: str) -> None:
        preview = original[:2] + "***" if len(original) > 3 else "***"
        self.findings.append({
            "path": json_path,
            "category": category,
            "originalPreview": preview,
            "maskedResult": masked,
        })
