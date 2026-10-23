# 🛡️ DataGuard API — Motor de Privacidad (Habeas Data Ley 1581 / PII Masking) & Forense Binario de Archivos

**DataGuard API** es un microservicio **100% Backend** en **Python 3.12 + FastAPI (Async) + Pydantic v2** diseñado para que cualquier aplicación, ERP o plataforma clínica en Colombia cumpla con la **Ley 1581 de 2012 (Habeas Data)** anonimizando datos personales/clínicos en estructuras JSON o textos libres, e inspeccionando forensemente archivos subidos en memoria mediante sus **Magic Bytes hexadecimales** y **Entropía de Shannon**.

![Python 3.12](https://img.shields.io/badge/Python-3.12_Slim-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Async_%2B_Pydantic_v2-009688?logo=fastapi&logoColor=white)
![Compliance](https://img.shields.io/badge/Compliance-Ley_1581_Habeas_Data_%26_HIPAA-10B981)
![Architecture](https://img.shields.io/badge/Architecture-Hexagonal_Rule_Engine-8A2BE2)
![Design Patterns](https://img.shields.io/badge/GoF_Patterns-Visitor_%7C_Decorator_%7C_Chain_of_Responsibility-F59E0B)
![Pytest](https://img.shields.io/badge/Tests-Pytest_Passing-0A9EDC?logo=pytest&logoColor=white)

---

## 🚀 Capacidades Principales

1. **🔒 Anonimización Recursiva de JSON y Texto Libre (`POST /api/v1/privacy/mask-json`, `/mask-text`):**
   - Detecta automáticamente **Cédulas Colombianas**, **NITs con DV**, **Celulares Colombianos (`+57 3xx`)**, **Correos Electrónicos** y **Tarjetas de Crédito (validadas con el Algoritmo de Luhn ISO/IEC 7812)**.
   - Soporta 3 estrategias de enmascaramiento intercambiables:
     - `REDACT`: Ocultamiento parcial (`315*****34`, `ca***@clinica.co`).
     - `DETERMINISTIC_TOKEN`: Pseudonimización consistente con `HMAC-SHA256` (`TKN_DOC_ID_8F9A1B2C`) que preserva la integridad referencial entre tablas de prueba.
     - `REVERSIBLE_VAULT`: Tokenización en bóveda criptográfica (`VLT_DOC_ID_...`) reversible mediante `POST /api/v1/privacy/unmask`.
2. **🔬 Inspector Forense Binario de Archivos (`POST /api/v1/forensics/inspect-base64`, `/inspect-upload`):**
   - Analiza los **Magic Bytes** reales de un archivo en memoria para detectar cuando un ejecutable (`ELF` de Linux o `MZ/PE` de Windows) o un script malicioso (`<?php`, `<script>`, `/Launch`) ha sido renombrado como `.pdf`, `.jpg` o `.xlsx`, calculando además la **Entropía Matemática de Shannon** ($0.00 - 8.00 \text{ bits/byte}$).
3. **🔑 Auditor Criptográfico de Contraseñas (`POST /api/v1/crypto/password-audit`):**
   - Calcula la entropía real en bits según el espacio de caracteres y deriva hashes seguros con `scrypt`.

---

## 🧩 Patrones de Diseño (GoF) Implementados

- **`Visitor Pattern` (`JsonTreeMaskingVisitor`):** Recorre árboles JSON de cualquier profundidad sin mutar el objeto original ni romper su esquema.
- **`Decorator Pattern` (`RedactionMaskDecorator`, `DeterministicHmacDecorator`, `ReversibleVaultDecorator`):** Envuelve dinámicamente el comportamiento de anonimización.
- **`Chain of Responsibility Pattern` (`MagicBytesSignatureInspector` $\rightarrow$ `ExtensionMismatchInspector` $\rightarrow$ `PolyglotPayloadInspector` $\rightarrow$ `ShannonEntropyInspector`):** Pipeline secuencial de análisis forense binario.

---

## 🐳 Despliegue Rápido (Docker Compose & ALpanel)

```bash
cp .env.example .env
docker compose up -d --build
```

- **Documentación Interactiva Scalar OpenAPI 3.1:** `http://localhost:8087/`
- **Swagger UI Clásico:** `http://localhost:8087/docs`
