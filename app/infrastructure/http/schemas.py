from typing import Any, List
from pydantic import BaseModel, Field


class MaskJsonRequest(BaseModel):
    mode: str = Field(
        default="REDACT",
        description="Estrategia Decorator: REDACT | DETERMINISTIC_TOKEN | REVERSIBLE_VAULT",
    )
    payload: Any = Field(
        ...,
        description="Objeto JSON o estructura anidada con datos sensibles (cédulas, NITs, celulares, tarjetas, emails)",
    )


class MaskTextRequest(BaseModel):
    mode: str = Field(default="REDACT", description="REDACT | DETERMINISTIC_TOKEN | REVERSIBLE_VAULT")
    text: str = Field(..., description="Texto libre, log de servidor o nota clínica a sanitizar")


class UnmaskVaultRequest(BaseModel):
    tokens: List[str] = Field(..., description="Lista de tokens VLT_* generados en modo REVERSIBLE_VAULT")


class InspectBase64FileRequest(BaseModel):
    filename: str = Field(default="documento_sospechoso.pdf")
    base64Content: str = Field(..., description="Contenido binario del archivo codificado en Base64")


class PasswordAuditRequest(BaseModel):
    password: str = Field(..., min_length=1)
