import base64
import unittest

from app.domain.chain.forensic_chain import audit_password_strength, execute_forensic_chain
from app.domain.decorators.masking_decorators import build_masker
from app.domain.visitor.json_masking_visitor import JsonTreeMaskingVisitor, is_valid_luhn


class TestDataGuardDomain(unittest.TestCase):
    def test_recursive_json_pii_masking_and_reversible_vault(self) -> None:
        vault_store = {}
        masker = build_masker("REVERSIBLE_VAULT", "test_secret_2026", vault_store)
        visitor = JsonTreeMaskingVisitor(masker)

        payload = {
            "paciente": {
                "nombre": "Carlos Andrés Gómez",
                "cedula": "1098765432",
                "celular": "+57 315 890 1234",
                "correo": "carlos.gomez@clinica.co",
            },
            "notaLibre": "Contacto alterno 3001234567 y NIT 900.123.456-8",
        }

        sanitized = visitor.visit(payload)
        self.assertGreaterEqual(len(visitor.findings), 5)

        masked_cedula = sanitized["paciente"]["cedula"]
        self.assertTrue(masked_cedula.startswith("VLT_DOC_ID_"))
        self.assertEqual(vault_store.get(masked_cedula), "1098765432")

    def test_forensic_chain_detects_spoofed_executable_and_polyglot_php(self) -> None:
        malicious_bytes = b"\x7fELF\x02\x01\x01\x00" + b"<?php system($_GET['cmd']); ?>"
        report = execute_forensic_chain("factura_proveedor.pdf", malicious_bytes)

        self.assertEqual(report["detectedMagicType"], "ELF_LINUX_EXECUTABLE")
        self.assertTrue(report["extensionSpoofed"])
        self.assertEqual(report["riskLevel"], "CRITICAL_MALICIOUS_SPOOFING")
        self.assertTrue(any("PHP_WEB_SHELL_PAYLOAD" in t for t in report["embeddedThreats"]))
        self.assertEqual(len(report["chainSteps"]), 4)

    def test_forensic_chain_accepts_genuine_pdf(self) -> None:
        genuine_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
        report = execute_forensic_chain("historia_clinica.pdf", genuine_pdf)

        self.assertEqual(report["detectedMagicType"], "PDF_DOCUMENT")
        self.assertFalse(report["extensionSpoofed"])
        self.assertEqual(report["riskLevel"], "SAFE")

    def test_luhn_and_password_entropy_auditor(self) -> None:
        self.assertTrue(is_valid_luhn("4532015112830366"))
        self.assertFalse(is_valid_luhn("4532015112830367"))

        audit = audit_password_strength("C0lombia#Lex2026!Secure")
        self.assertEqual(audit["strengthRating"], "VERY_STRONG")
        self.assertTrue(str(audit["scryptHashSample"]).startswith("scrypt$"))


if __name__ == "__main__":
    unittest.main()
