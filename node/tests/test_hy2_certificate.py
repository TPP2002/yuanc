"""Public, disposable certificate vectors; private keys never leave memory."""

import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def test_self_signed_test_vector(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exitnode")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
                   .not_valid_after(datetime(2036, 1, 1, tzinfo=UTC))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("exitnode")]), False)
                   .sign(key, hashes.SHA256()))
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "hy2-public-test-vector.pem").write_bytes(pem)
    parsed = x509.load_pem_x509_certificate(pem)
    assert parsed.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["exitnode"]
    parsed.public_key().verify(parsed.signature, parsed.tbs_certificate_bytes,
                               ec.ECDSA(parsed.signature_hash_algorithm))


def test_golden_certificate_is_self_signed_and_matches_name():
    data = json.loads((Path(__file__).parent / "golden/proxy/inputs.json").read_text("utf-8"))
    ctx = data["context"]
    cert = x509.load_pem_x509_certificate("\n".join(ctx["hy2_certificate"]).encode("ascii"))
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.subject == cert.issuer
    assert ctx["hy2_server_name"] in cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                             ec.ECDSA(cert.signature_hash_algorithm))
