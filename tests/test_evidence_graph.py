"""
Unit tests for Directed Evidence Graph construction, node relationships, and critical path analysis.
"""
import pytest
from backend.graph_engine import EvidenceGraph, EvidenceGraphBuilder

def test_evidence_graph_linking():
    eg = EvidenceGraph()

    # Create provenance chain: Message -> Attachment -> Link -> Landing -> Action
    m_id = eg.add_node("msg_1", "Phishing Email", "MESSAGE", risk_score=50.0)
    att_id = eg.add_node("att_1", "invoice.svg", "ATTACHMENT", risk_score=85.0)
    link_id = eg.add_node("link_1", "http://evil.com", "LINK", risk_score=70.0)
    land_id = eg.add_node("land_1", "evil.com/login", "LANDING_PAGE", risk_score=90.0)
    act_id = eg.add_node("act_1", "Harvest Credentials", "REQUESTED_ACTION", risk_score=95.0)

    eg.add_edge(m_id, att_id, "EMBEDS_ATTACHMENT")
    eg.add_edge(att_id, link_id, "EXTRACTED_FROM_PAYLOAD")
    eg.add_edge(link_id, land_id, "RESOLVES_TO_LANDING")
    eg.add_edge(land_id, act_id, "REQUESTS_ACTION")

    graph_dict = eg.to_dict()

    assert graph_dict["total_nodes"] == 5
    assert graph_dict["total_edges"] == 4
    assert len(graph_dict["critical_risk_path"]) == 5
    assert graph_dict["critical_risk_path"][0] == "msg_1"
    assert graph_dict["critical_risk_path"][-1] == "act_1"

def test_evidence_graph_builder_from_email():
    email_data = {
        "subject": "Action Required: Verify Account",
        "from": "Admin <admin@fake-alert.com>",
        "risk_score": 75.0,
        "links": [{"href": "http://evil-landing.xyz/login"}],
        "auth_results": {"spf": "FAIL", "dkim": "FAIL"}
    }
    attachment_results = [{
        "filename": "payload.svg",
        "risk_score": 80.0,
        "smuggling_detected": True,
        "extracted_urls": ["http://smuggled-payload.xyz/drop"]
    }]
    quishing_results = [{
        "payload": "http://qr-quish.xyz/auth",
        "is_url": True,
        "risk_score": 40.0
    }]
    url_results = [{
        "url": "http://evil-landing.xyz/login",
        "host": "evil-landing.xyz",
        "domain": "evil-landing.xyz",
        "risk_score": 80.0,
        "redirect_hops": ["http://hop1.xyz", "http://hop2.xyz"],
        "final_url": "http://evil-landing.xyz/login",
        "destination_status": "ACTIVE"
    }]

    eg = EvidenceGraphBuilder.build_from_email_analysis(
        email_data=email_data,
        attachment_results=attachment_results,
        quishing_results=quishing_results,
        url_results=url_results
    )
    graph_dict = eg.to_dict()

    assert graph_dict["total_nodes"] >= 6
    assert any(n["type"] == "MESSAGE" for n in graph_dict["nodes"])
    assert any(n["type"] == "ATTACHMENT" for n in graph_dict["nodes"])
    assert any(n["type"] == "QR_CODE" for n in graph_dict["nodes"])
    assert any(n["type"] == "REDIRECT_HOP" for n in graph_dict["nodes"])
    assert any(n["type"] == "REQUESTED_ACTION" for n in graph_dict["nodes"])
