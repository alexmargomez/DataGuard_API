import base64
import os
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.application.use_cases.privacy_use_case import PrivacyMaskingUseCase
from app.domain.chain.forensic_chain import audit_password_strength, execute_forensic_chain
from app.domain.ports.vault_port import InMemoryTtlVaultAdapter
from app.infrastructure.http.schemas import (
    InspectBase64FileRequest,
    MaskJsonRequest,
    MaskTextRequest,
    PasswordAuditRequest,
    UnmaskVaultRequest,
)

app = FastAPI(
    title="DataGuard API — Motor de Privacidad (Habeas Data Ley 1581) & Forense Binario",
    version="1.0.0",
    description=(
        "Microservicio 100% Backend en Python 3.12 + FastAPI + Pydantic v2 para anonimización recursiva "
        "de datos personales/clínicos (Visitor + Decorator Patterns + TokenVaultPort TTL) e inspección forense de archivos "
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
VAULT_ADAPTER = InMemoryTtlVaultAdapter(max_capacity=5000, ttl_seconds=3600.0)
PRIVACY_USE_CASE = PrivacyMaskingUseCase(vault_secret=VAULT_SECRET, vault_port=VAULT_ADAPTER)


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
        "architecture": "Hexagonal Rule Engine (Visitor + Decorator + Chain of Responsibility + TokenVaultPort TTL)",
        "vaultTokensStored": PRIVACY_USE_CASE.vault_size,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/privacy/mask-json", tags=["2. Privacidad & Habeas Data (Ley 1581)"])
async def mask_json_payload(req: MaskJsonRequest) -> Dict[str, Any]:
    return PRIVACY_USE_CASE.mask_json(req.mode, req.payload)


@app.post("/api/v1/privacy/mask-text", tags=["2. Privacidad & Habeas Data (Ley 1581)"])
async def mask_free_text(req: MaskTextRequest) -> Dict[str, Any]:
    return PRIVACY_USE_CASE.mask_text(req.mode, req.text)


@app.post("/api/v1/privacy/unmask", tags=["2. Privacidad & Habeas Data (Ley 1581)"])
async def unmask_vault_tokens(req: UnmaskVaultRequest) -> Dict[str, Any]:
    return PRIVACY_USE_CASE.unmask_tokens(req.tokens)


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
