import base64
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.domain.chain.forensic_chain import audit_password_strength, execute_forensic_chain
from app.domain.decorators.masking_decorators import build_masker
from app.domain.visitor.json_masking_visitor import JsonTreeMaskingVisitor

app = FastAPI(
    title="DataGuard API — Motor de Privacidad (Habeas Data Ley 1581) & Forense Binario",
    version="1.0.0",
    description=(
        "Microservicio 100% Backend en Python 3.12 + FastAPI + Pydantic v2 para anonimización recursiva "
        "de datos personales/clínicos (Visitor + Decorator Patterns) e inspección forense de archivos "
        "binarios por Magic Bytes y Entropía de Shannon (Chain of Responsibility Pattern)."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VAULT_SECRET = os.getenv("VAULT_MASTER_SECRET", "dataguard_ley1581_master_secret_2026")
REVERSIBLE_VAULT_STORE: Dict[str, str] = {}


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


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def scalar_docs_ui() -> str:
    return """<!doctype html>
<html>
  <head>
    <title>DataGuard API — Habeas Data Ley 1581 & Binary Forensics (OpenAPI 3.1)</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="/openapi.json" data-configuration='{"theme":"purple","darkMode":true}'></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>"""


@app.get("/api/v1/health", tags=["1. Salud & Telemetría"])
async def health() -> Dict[str, Any]:
    return {
        "status": "UP",
        "service": "DataGuard API (Python 3.12 + FastAPI + Pydantic v2)",
        "architecture": "Hexagonal Rule Engine (Visitor + Decorator + Chain of Responsibility)",
        "vaultTokensStored": len(REVERSIBLE_VAULT_STORE),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/privacy/mask-json", tags=["2. Privacidad & Habeas Data (Ley 1581)"])
async def mask_json_payload(req: MaskJsonRequest) -> Dict[str, Any]:
    masker = build_masker(req.mode, VAULT_SECRET, REVERSIBLE_VAULT_STORE)
    visitor = JsonTreeMaskingVisitor(masker)
    sanitized = visitor.visit(req.payload)
    return {
        "complianceStandard": "Ley 1581 de 2012 (Habeas Data Colombia) / HIPAA Safe Harbor",
        "strategyApplied": req.mode.upper(),
        "totalPiiDetected": len(visitor.findings),
        "sanitizedPayload": sanitized,
        "auditFindings": visitor.findings,
    }


@app.post("/api/v1/privacy/mask-text", tags=["2. Privacidad & Habeas Data (Ley 1581)"])
async def mask_free_text(req: MaskTextRequest) -> Dict[str, Any]:
    masker = build_masker(req.mode, VAULT_SECRET, REVERSIBLE_VAULT_STORE)
    visitor = JsonTreeMaskingVisitor(masker)
    sanitized_text = visitor.visit_string(req.text)
    return {
        "strategyApplied": req.mode.upper(),
        "totalPiiDetected": len(visitor.findings),
        "sanitizedText": sanitized_text,
        "auditFindings": visitor.findings,
    }


@app.post("/api/v1/privacy/unmask", tags=["2. Privacidad & Habeas Data (Ley 1581)"])
async def unmask_vault_tokens(req: UnmaskVaultRequest) -> Dict[str, Any]:
    resolved: Dict[str, Optional[str]] = {}
    for tkn in req.tokens:
        resolved[tkn] = REVERSIBLE_VAULT_STORE.get(tkn)
    return {
        "requestedCount": len(req.tokens),
        "resolved": resolved,
    }


@app.post("/api/v1/forensics/inspect-base64", tags=["3. Inspección Forense Binaria (Magic Bytes)"])
async def inspect_base64_file(req: InspectBase64FileRequest) -> Dict[str, Any]:
    try:
        raw_bytes = base64.b64decode(req.base64Content)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Base64 inválido: {exc}") from exc
    return execute_forensic_chain(req.filename, raw_bytes)


@app.post("/api/v1/forensics/inspect-upload", tags=["3. Inspección Forense Binaria (Magic Bytes)"])
async def inspect_uploaded_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    raw_bytes = await file.read()
    return execute_forensic_chain(file.filename or "upload.bin", raw_bytes)


@app.post("/api/v1/crypto/password-audit", tags=["4. Auditoría Criptográfica"])
async def password_audit(req: PasswordAuditRequest) -> Dict[str, Any]:
    return audit_password_strength(req.password)
