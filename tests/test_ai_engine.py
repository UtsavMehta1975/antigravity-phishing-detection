"""
Unit tests for AI Engine: ML URL Classifier and Social Engineering Pretext Copilot.
"""
import pytest
from backend.ai_engine.ml_classifier import MLURLClassifier
from backend.ai_engine.llm_advisor import AISecurityAdvisor

def test_ml_url_classifier_phishing_sample():
    classifier = MLURLClassifier()
    # Malicious test lure with suspicious TLD and executable
    res = classifier.predict("http://login-microsoft-security.top/auth/update.exe")
    assert res["ai_classification"] == "PHISHING"
    assert res["phishing_probability"] >= 65.0
    assert "Direct Executable Payload" in res["top_ai_signals"] or "Suspicious TLD" in res["top_ai_signals"]

def test_ml_url_classifier_benign_sample():
    classifier = MLURLClassifier()
    res = classifier.predict("https://www.google.com/search?q=cybersecurity")
    assert res["ai_classification"] == "BENIGN"
    assert res["phishing_probability"] < 50.0

def test_ai_security_advisor_pretext_analysis():
    advisor = AISecurityAdvisor()
    email_text = "URGENT: Your Microsoft IT corporate account will be suspended within 24 hours. Verify now."
    res = advisor.analyze_social_engineering(email_text, indicators=["BRAND_IMPERSONATION"])
    
    assert res["ai_copilot_enabled"] is True
    assert "Corporate Authority & IT Impersonation" in res["primary_pretext_category"]
    assert res["manipulation_score"] >= 40.0
    assert len(res["ai_recommended_playbook"]) >= 3
    assert any("Artificial Time Constraint" in tactic for tactic in res["coercion_tactics_detected"])
