"""
End-to-end unit and integration tests for Detection Pipeline, NIST XAI Engine, and UNKNOWN state handling.
"""
import pytest
from backend.pipeline import DetectionPipeline
from backend.database import init_db, save_override, list_overrides

@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()

@pytest.mark.asyncio
async def test_e2e_email_analysis_phishing():
    pipeline = DetectionPipeline()

    raw_eml = b"""From: "Microsoft Security Team" <admin@sec-m365-verify.top>
To: victim@company.com
Subject: URGENT: Password Expired - Action Required
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Your Office 365 password has expired. Click below to verify:</p>
<a href="http://login.microsoft.security-verify.top/auth">https://login.microsoft.com/account</a>
</body>
</html>
"""

    result = await pipeline.analyze_email(raw_eml)

    assert result["verdict"] in ["PHISHING", "CAUTION"]
    assert result["confidence_score"] >= 65.0
    # NIST XAI checks
    assert "recipient_view" in result
    assert "analyst_view" in result
    assert "evidence_graph" in result

    # Check recipient view clarity
    rec_view = result["recipient_view"]
    assert rec_view["badge_color"] == "crimson"
    assert "Do NOT click" in rec_view["recommended_action"]

    # Check analyst view NIST principles
    analyst = result["analyst_view"]
    nist = analyst["nist_evaluation"]
    assert "principle_1_explanation" in nist
    assert "principle_2_meaningfulness" in nist
    assert "principle_3_accuracy" in nist
    assert "principle_4_knowledge_limits" in nist

@pytest.mark.asyncio
async def test_e2e_unknown_state_evasion():
    pipeline = DetectionPipeline()

    # URL simulating a CAPTCHA-guarded evasion wall
    test_url = "https://captcha-guarded-phish.top/login"
    result = await pipeline.analyze_url(test_url)

    assert result["analyst_view"]["destination_status"] == "UNKNOWN"
    assert any("CAPTCHA" in ev for ev in result["analyst_view"]["evasion_techniques"])
    # NIST Knowledge Limits must disclose the wall
    knowledge_limits = result["analyst_view"]["nist_evaluation"]["principle_4_knowledge_limits"]
    assert any("CAPTCHA" in limit for limit in knowledge_limits)

def test_auditable_override_storage():
    override_id = save_override(
        scan_id="test_scan_101",
        target="http://internal-tool.company.com",
        feedback_type="false_positive",
        override_verdict="BENIGN",
        analyst_notes="Verified internal SSO service"
    )
    assert override_id > 0
    all_overrides = list_overrides()
    assert any(o["scan_id"] == "test_scan_101" for o in all_overrides)
