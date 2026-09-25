"""
Unit tests for HTML & SVG Smuggling, PDF and DOCX multi-modal analysis.
"""
import pytest
from backend.parsers.attachment_analyzer import AttachmentAnalysisResult

def test_svg_smuggling_foreignobject_and_script():
    # Malicious SVG containing <foreignObject>, dynamic Blob creation and script tags
    svg_payload = b"""<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
      <foreignObject width="100%" height="100%">
        <div xmlns="http://www.w3.org/1999/xhtml">
          <script>
            const b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA";
            const blob = new Blob([window.atob(b64)], {type: 'application/octet-stream'});
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = "payroll_update.exe";
            link.click();
          </script>
        </div>
      </foreignObject>
    </svg>"""

    analyzer = AttachmentAnalysisResult(filename="invoice_review.svg", content=svg_payload)
    result = analyzer.analyze()

    assert result["smuggling_detected"] is True
    assert result["risk_score"] >= 80.0
    anomalies = [a["category"] for a in result["anomalies"]]
    assert "SVG_FOREIGNOBJECT_SMUGGLING" in anomalies
    assert "SMUGGLING_BLOB_URL_CREATION" in anomalies
    assert "SMUGGLING_BASE64_ATOB_DECODING" in anomalies
    assert "SMUGGLING_AUTOMATED_DOWNLOAD_TRIGGER" in anomalies

def test_html_smuggling_blob_download():
    html_payload = b"""<!DOCTYPE html>
    <html>
    <head><title>Secure Document</title></head>
    <body>
    <script>
      var raw = window.atob("SGVsbG8gV29ybGQ=");
      var blob = new Blob([raw], {type: "application/pdf"});
      var url = window.webkitURL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = "document.pdf";
      a.click();
    </script>
    </body>
    </html>"""

    analyzer = AttachmentAnalysisResult(filename="secure_share.html", content=html_payload)
    result = analyzer.analyze()

    assert result["smuggling_detected"] is True
    assert result["risk_score"] >= 65.0
    anomalies = [a["category"] for a in result["anomalies"]]
    assert "SMUGGLING_BLOB_URL_CREATION" in anomalies
    assert "SMUGGLING_DYNAMIC_ANCHOR_INJECTION" in anomalies

def test_pdf_embedded_javascript_and_launch():
    # Raw PDF stream containing /JavaScript and /Launch action
    raw_pdf = b"""%PDF-1.4
    1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >> endobj
    3 0 obj << /Type /Action /S /JavaScript /JS (app.alert("Security Update");) >> endobj
    4 0 obj << /Type /Action /S /Launch /F (cmd.exe) >> endobj
    xref
    trailer << /Root 1 0 R >>
    %%EOF"""

    analyzer = AttachmentAnalysisResult(filename="document.pdf", content=raw_pdf)
    result = analyzer.analyze()

    assert result["risk_score"] >= 70.0
    anom_cats = [a["category"] for a in result["anomalies"]]
    assert "PDF_EMBEDDED_JAVASCRIPT" in anom_cats or "PDF_LAUNCH_ACTION" in anom_cats

def test_clean_svg():
    clean_svg = b"""<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
      <circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />
    </svg>"""

    analyzer = AttachmentAnalysisResult(filename="logo.svg", content=clean_svg)
    result = analyzer.analyze()

    assert result["smuggling_detected"] is False
    assert result["risk_score"] == 0.0
