"""
Unit tests for Computer Vision QR Code (Quishing) Decoder.
"""
import io
import qrcode
import pytest
from backend.parsers.quishing_decoder import QuishingDecoder

def test_quishing_qr_code_decode():
    # 1. Generate a genuine QR code targeting a phishing URL
    target_url = "https://login-office365-verify.top/auth"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(target_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_bytes = buf.getvalue()

    # 2. Decode using QuishingDecoder
    decoder = QuishingDecoder()
    results = decoder.decode_image_bytes(qr_bytes)

    assert len(results) > 0
    assert results[0]["payload"] == target_url
    assert results[0]["is_url"] is True
    assert results[0]["technique"] == "QUISHING_ATTACK_VECTOR"
