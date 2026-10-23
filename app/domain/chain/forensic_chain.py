import hashlib
import math
import os
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ForensicInspectionContext:
    filename: str
    declared_extension: str
    byte_size: int
    raw_bytes: bytes
    detected_magic_type: str = "UNKNOWN_OR_TEXT"
    magic_hex_header: str = ""
    extension_spoofed: bool = False
    embedded_threats: List[str] = field(default_factory=list)
    shannon_entropy: float = 0.0
    risk_level: str = "SAFE"
    sha256_hash: str = ""
    inspector_steps: List[Dict[str, str]] = field(default_factory=list)


class ForensicHandler(ABC):
    """Chain of Responsibility Pattern — Eslabón abstracto para inspección forense de archivos en memoria."""

    def __init__(self) -> None:
        self._next: Optional["ForensicHandler"] = None

    def set_next(self, handler: "ForensicHandler") -> "ForensicHandler":
        self._next = handler
        return handler

    def handle(self, ctx: ForensicInspectionContext) -> ForensicInspectionContext:
        self.inspect(ctx)
        if self._next is not None:
            return self._next.handle(ctx)
        return ctx

    @abstractmethod
    def inspect(self, ctx: ForensicInspectionContext) -> None:
        pass


class MagicBytesSignatureInspector(ForensicHandler):
    """Eslabón 1: Identifica el formato real del archivo leyendo sus primeros bytes hexadecimales (Magic Numbers)."""

    SIGNATURES = [
        (b"%PDF-", "PDF_DOCUMENT"),
        (b"\x89PNG\r\n\x1a\n", "PNG_IMAGE"),
        (b"\xff\xd8\xff", "JPEG_IMAGE"),
        (b"GIF87a", "GIF_IMAGE"),
        (b"GIF89a", "GIF_IMAGE"),
        (b"PK\x03\x04", "ZIP_OR_OFFICE_OPENXML"),
        (b"\x7fELF", "ELF_LINUX_EXECUTABLE"),
        (b"MZ", "WINDOWS_PE_EXECUTABLE"),
        (b"#!/bin/sh", "SHELL_SCRIPT_EXECUTABLE"),
        (b"#!/bin/bash", "SHELL_SCRIPT_EXECUTABLE"),
    ]

    def inspect(self, ctx: ForensicInspectionContext) -> None:
        header = ctx.raw_bytes[:16]
        ctx.magic_hex_header = header.hex().upper()
        ctx.sha256_hash = hashlib.sha256(ctx.raw_bytes).hexdigest()

        for sig_bytes, label in self.SIGNATURES:
            if ctx.raw_bytes.startswith(sig_bytes):
                ctx.detected_magic_type = label
                break

        ctx.inspector_steps.append({
            "step": "1. MagicBytesSignatureInspector",
            "result": f"Cabecera hexadecimal [{ctx.magic_hex_header[:16]}...] clasificada como {ctx.detected_magic_type}",
        })


class ExtensionMismatchInspector(ForensicHandler):
    """Eslabón 2: Detecta ataques de extensión camuflada (ej. malware.exe renombrado como factura.pdf)."""

    EXPECTED_MAP = {
        ".pdf": {"PDF_DOCUMENT"},
        ".png": {"PNG_IMAGE"},
        ".jpg": {"JPEG_IMAGE"},
        ".jpeg": {"JPEG_IMAGE"},
        ".gif": {"GIF_IMAGE"},
        ".zip": {"ZIP_OR_OFFICE_OPENXML"},
        ".docx": {"ZIP_OR_OFFICE_OPENXML"},
        ".xlsx": {"ZIP_OR_OFFICE_OPENXML"},
    }

    DANGEROUS_BINARY_TYPES = {"ELF_LINUX_EXECUTABLE", "WINDOWS_PE_EXECUTABLE", "SHELL_SCRIPT_EXECUTABLE"}

    def inspect(self, ctx: ForensicInspectionContext) -> None:
        ext = ctx.declared_extension.lower()
        if ctx.detected_magic_type in self.DANGEROUS_BINARY_TYPES:
            ctx.extension_spoofed = True
            ctx.risk_level = "CRITICAL_MALICIOUS_SPOOFING"
            ctx.embedded_threats.append(
                f"Ejecutable binario real ({ctx.detected_magic_type}) camuflado con extensión '{ext}'"
            )
        elif ext in self.EXPECTED_MAP and ctx.detected_magic_type not in self.EXPECTED_MAP[ext]:
            ctx.extension_spoofed = True
            ctx.risk_level = "HIGH_EXTENSION_MISMATCH"
            ctx.embedded_threats.append(
                f"La extensión declarada '{ext}' no coincide con la firma binaria real ({ctx.detected_magic_type})"
            )

        ctx.inspector_steps.append({
            "step": "2. ExtensionMismatchInspector",
            "result": "ALERTA SPOOFING" if ctx.extension_spoofed else "Extensión coherente con Magic Bytes",
        })


class PolyglotPayloadInspector(ForensicHandler):
    """Eslabón 3: Escanea el flujo binario buscando scripts ocultos o payloads políglotas (PHP, JS, PDF Launch)."""

    PATTERNS = [
        (b"<?php", "PHP_WEB_SHELL_PAYLOAD"),
        (b"<script", "EMBEDDED_HTML_XSS_SCRIPT"),
        (b"/JavaScript", "PDF_EMBEDDED_JAVASCRIPT_ACTION"),
        (b"/Launch", "PDF_SYSTEM_COMMAND_LAUNCH"),
        (b"powershell -enc", "POWERSHELL_ENCODED_PAYLOAD"),
    ]

    def inspect(self, ctx: ForensicInspectionContext) -> None:
        lower_bytes = ctx.raw_bytes.lower()
        found_now = []
        for pattern, threat_name in self.PATTERNS:
            if pattern.lower() in lower_bytes:
                found_now.append(threat_name)
                ctx.embedded_threats.append(f"Payload oculto detectado en binario: {threat_name}")

        if found_now and ctx.risk_level == "SAFE":
            ctx.risk_level = "CRITICAL_POLYGLOT_PAYLOAD"

        ctx.inspector_steps.append({
            "step": "3. PolyglotPayloadInspector",
            "result": f"Payloads detectados: {', '.join(found_now)}" if found_now else "0 firmas de código malicioso embebido",
        })


class ShannonEntropyInspector(ForensicHandler):
    """Eslabón 4: Calcula la Entropía de Shannon H(X) en bits/byte (0.0 a 8.0) para detectar cifrado/ofuscación."""

    def inspect(self, ctx: ForensicInspectionContext) -> None:
        if ctx.byte_size == 0:
            ctx.shannon_entropy = 0.0
            return

        counts = Counter(ctx.raw_bytes)
        total = float(ctx.byte_size)
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
        ctx.shannon_entropy = round(entropy, 4)

        ctx.inspector_steps.append({
            "step": "4. ShannonEntropyInspector",
            "result": f"Entropía matemática = {ctx.shannon_entropy} bits/byte (Escala 0.00 - 8.00)",
        })


def execute_forensic_chain(filename: str, raw_bytes: bytes) -> Dict[str, object]:
    _, ext = os.path.splitext(filename or "sample.bin")
    ctx = ForensicInspectionContext(
        filename=filename or "sample.bin",
        declared_extension=ext or ".bin",
        byte_size=len(raw_bytes),
        raw_bytes=raw_bytes,
    )

    step1 = MagicBytesSignatureInspector()
    step2 = ExtensionMismatchInspector()
    step3 = PolyglotPayloadInspector()
    step4 = ShannonEntropyInspector()
    step1.set_next(step2).set_next(step3).set_next(step4)

    step1.handle(ctx)

    return {
        "filename": ctx.filename,
        "declaredExtension": ctx.declared_extension,
        "byteSize": ctx.byte_size,
        "sha256Hash": ctx.sha256_hash,
        "magicHexHeader": ctx.magic_hex_header,
        "detectedMagicType": ctx.detected_magic_type,
        "extensionSpoofed": ctx.extension_spoofed,
        "shannonEntropyBitsPerByte": ctx.shannon_entropy,
        "riskLevel": ctx.risk_level,
        "embeddedThreats": ctx.embedded_threats,
        "chainSteps": ctx.inspector_steps,
    }


def audit_password_strength(password: str) -> Dict[str, object]:
    pwd = password or ""
    pool_size = 0
    if any(c.islower() for c in pwd):
        pool_size += 26
    if any(c.isupper() for c in pwd):
        pool_size += 26
    if any(c.isdigit() for c in pwd):
        pool_size += 10
    if any(not c.isalnum() for c in pwd):
        pool_size += 32

    entropy_bits = round(len(pwd) * math.log2(max(pool_size, 1)), 2) if pwd else 0.0
    salt = os.urandom(16)
    derived_scrypt = hashlib.scrypt(pwd.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)

    strength = "WEAK"
    if entropy_bits >= 80:
        strength = "VERY_STRONG"
    elif entropy_bits >= 60:
        strength = "STRONG"
    elif entropy_bits >= 40:
        strength = "MODERATE"

    return {
        "length": len(pwd),
        "characterPoolSize": pool_size,
        "entropyBits": entropy_bits,
        "strengthRating": strength,
        "scryptHashSample": f"scrypt$16384$8$1${salt.hex()}${derived_scrypt.hex()}",
    }
