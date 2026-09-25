"""
Directed Evidence Graph Engine.
Constructs a provenance graph mapping:
Message -> Attachment -> QR/Link -> Redirect Hops -> Final Landing Page -> Requested Action
Calculates critical risk paths and exports interactive network structures for analyst view.
"""
import uuid
from typing import Dict, Any, List, Optional
import networkx as nx

class EvidenceGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.root_node_id: Optional[str] = None

    def add_node(self, node_id: str, label: str, node_type: str, risk_score: float = 0.0, attributes: Optional[Dict[str, Any]] = None) -> str:
        attrs = attributes or {}
        self.graph.add_node(
            node_id,
            id=node_id,
            label=label,
            node_type=node_type,
            risk_score=risk_score,
            attributes=attrs
        )
        if not self.root_node_id:
            self.root_node_id = node_id
        return node_id

    def add_edge(self, source_id: str, target_id: str, relationship: str, risk_weight: float = 1.0, details: Optional[Dict[str, Any]] = None):
        self.graph.add_edge(
            source_id,
            target_id,
            relationship=relationship,
            risk_weight=risk_weight,
            details=details or {}
        )

    def to_dict(self) -> Dict[str, Any]:
        """Converts networkx graph to Cytoscape/Vis.js compatible JSON format."""
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({
                "id": n,
                "label": data.get("label", n),
                "type": data.get("node_type", "UNKNOWN"),
                "risk_score": data.get("risk_score", 0.0),
                "attributes": data.get("attributes", {})
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "relationship": data.get("relationship", "CONNECTS_TO"),
                "risk_weight": data.get("risk_weight", 1.0),
                "details": data.get("details", {})
            })

        critical_path = self.find_critical_risk_path()

        return {
            "root_node_id": self.root_node_id,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges,
            "critical_risk_path": critical_path
        }

    def find_critical_risk_path(self) -> List[str]:
        """Finds the path in the graph that accumulates the maximum risk."""
        if not self.root_node_id or len(self.graph) == 0:
            return []

        # Find leaf nodes (nodes with out_degree == 0)
        leaves = [n for n in self.graph.nodes() if self.graph.out_degree(n) == 0]
        if not leaves:
            return [self.root_node_id]

        max_risk = -1.0
        best_path: List[str] = []

        for leaf in leaves:
            if nx.has_path(self.graph, self.root_node_id, leaf):
                all_paths = nx.all_simple_paths(self.graph, self.root_node_id, leaf)
                for path in all_paths:
                    path_risk = sum(self.graph.nodes[n].get("risk_score", 0.0) for n in path)
                    if path_risk > max_risk:
                        max_risk = path_risk
                        best_path = path

        return best_path


class EvidenceGraphBuilder:
    @staticmethod
    def build_from_email_analysis(email_data: Dict[str, Any],
                                  attachment_results: List[Dict[str, Any]],
                                  quishing_results: List[Dict[str, Any]],
                                  url_results: List[Dict[str, Any]]) -> EvidenceGraph:
        """
        Assembles complete provenance chain:
        Message -> Attachment -> QR/Link -> Redirect Hops -> Landing Page -> Action
        """
        eg = EvidenceGraph()

        # 1. Message Node
        msg_id = f"msg_{uuid.uuid4().hex[:8]}"
        subject = email_data.get("subject") or "No Subject"
        sender = email_data.get("from") or "Unknown Sender"
        msg_risk = email_data.get("risk_score", 0.0)
        eg.add_node(
            msg_id,
            label=f"Message: {subject[:28]}...",
            node_type="MESSAGE",
            risk_score=msg_risk,
            attributes={
                "from": sender,
                "subject": subject,
                "auth_results": email_data.get("auth_results", {}),
                "reply_to": email_data.get("reply_to", "")
            }
        )

        # 2. Attachments
        for att in attachment_results:
            att_id = f"att_{uuid.uuid4().hex[:8]}"
            att_label = f"Attachment: {att.get('filename')}"
            eg.add_node(
                att_id,
                label=att_label,
                node_type="ATTACHMENT",
                risk_score=att.get("risk_score", 0.0),
                attributes={
                    "filename": att.get("filename"),
                    "smuggling_detected": att.get("smuggling_detected", False),
                    "anomalies": att.get("anomalies", [])
                }
            )
            eg.add_edge(msg_id, att_id, relationship="EMBEDS_ATTACHMENT", risk_weight=att.get("risk_score", 0.0))

            # If attachment had extracted URLs
            for url in att.get("extracted_urls", []):
                link_id = f"link_{uuid.uuid4().hex[:8]}"
                eg.add_node(
                    link_id,
                    label=f"Smuggled URL: {url[:30]}...",
                    node_type="LINK",
                    risk_score=60.0,
                    attributes={"url": url, "source": "attachment_smuggling"}
                )
                eg.add_edge(att_id, link_id, relationship="EXTRACTED_FROM_PAYLOAD", risk_weight=60.0)

        # 3. Quishing / QR Codes
        for qr in quishing_results:
            qr_id = f"qr_{uuid.uuid4().hex[:8]}"
            payload = qr.get("payload", "")
            eg.add_node(
                qr_id,
                label=f"QR Code: {payload[:28]}...",
                node_type="QR_CODE",
                risk_score=qr.get("risk_score", 40.0),
                attributes=qr
            )
            eg.add_edge(msg_id, qr_id, relationship="EMBEDS_QR", risk_weight=qr.get("risk_score", 40.0))

            # Connect QR to target link
            if qr.get("is_url"):
                target_link_id = f"link_{uuid.uuid4().hex[:8]}"
                eg.add_node(
                    target_link_id,
                    label=f"Quishing Link: {payload[:30]}...",
                    node_type="LINK",
                    risk_score=qr.get("risk_score", 40.0),
                    attributes={"url": payload, "source": "qr_decoder"}
                )
                eg.add_edge(qr_id, target_link_id, relationship="RESOLVES_TO_URL", risk_weight=40.0)

        # 4. Email Body Hyperlinks & Hops
        for u in url_results:
            u_id = f"link_{uuid.uuid4().hex[:8]}"
            raw_url = u.get("url", "")
            u_risk = u.get("risk_score", 0.0)
            eg.add_node(
                u_id,
                label=f"Link: {u.get('host', raw_url)[:25]}",
                node_type="LINK",
                risk_score=u_risk,
                attributes=u
            )
            eg.add_edge(msg_id, u_id, relationship="CONTAINS_HYPERLINK", risk_weight=u_risk)

            # Check redirect hops if present
            hops = u.get("redirect_hops", [])
            last_hop_id = u_id
            for idx, hop_url in enumerate(hops):
                hop_id = f"hop_{uuid.uuid4().hex[:8]}"
                eg.add_node(
                    hop_id,
                    label=f"Hop {idx+1}: {hop_url[:25]}",
                    node_type="REDIRECT_HOP",
                    risk_score=20.0,
                    attributes={"hop_url": hop_url, "hop_index": idx + 1}
                )
                eg.add_edge(last_hop_id, hop_id, relationship="REDIRECTS_TO", risk_weight=20.0)
                last_hop_id = hop_id

            # Final Landing Page
            final_url = u.get("final_url", raw_url)
            landing_id = f"landing_{uuid.uuid4().hex[:8]}"
            destination_status = u.get("destination_status", "ACTIVE")
            landing_risk = u_risk
            if destination_status == "UNKNOWN":
                landing_risk = max(landing_risk, 60.0)

            eg.add_node(
                landing_id,
                label=f"Landing: {u.get('domain', 'destination')}",
                node_type="LANDING_PAGE",
                risk_score=landing_risk,
                attributes={
                    "final_url": final_url,
                    "destination_status": destination_status,
                    "evasion_technique": u.get("evasion_technique", None),
                    "rdap_age_days": u.get("rdap_age_days", None),
                    "threat_feed_matches": u.get("threat_matches", [])
                }
            )
            eg.add_edge(last_hop_id, landing_id, relationship="RESOLVES_TO_LANDING", risk_weight=landing_risk)

            # Requested Action Node (if detected credential prompt or download)
            action_type = u.get("requested_action") or ("Harvest Credentials" if u_risk >= 50 else None)
            if action_type:
                action_id = f"action_{uuid.uuid4().hex[:8]}"
                eg.add_node(
                    action_id,
                    label=f"Action: {action_type}",
                    node_type="REQUESTED_ACTION",
                    risk_score=85.0 if "Harvest" in action_type else 50.0,
                    attributes={"action": action_type}
                )
                eg.add_edge(landing_id, action_id, relationship="REQUESTS_ACTION", risk_weight=85.0)

        return eg

    @staticmethod
    def build_from_url_analysis(url_result: Dict[str, Any]) -> EvidenceGraph:
        """Assembles evidence graph for a standalone URL scan."""
        eg = EvidenceGraph()
        root_url = url_result.get("url", "")
        root_id = f"root_{uuid.uuid4().hex[:8]}"
        u_risk = url_result.get("risk_score", 0.0)

        eg.add_node(
            root_id,
            label=f"URL: {url_result.get('host', root_url)[:25]}",
            node_type="LINK",
            risk_score=u_risk,
            attributes=url_result
        )

        hops = url_result.get("redirect_hops", [])
        last_id = root_id
        for idx, hop_url in enumerate(hops):
            hop_id = f"hop_{uuid.uuid4().hex[:8]}"
            eg.add_node(
                hop_id,
                label=f"Hop {idx+1}: {hop_url[:25]}",
                node_type="REDIRECT_HOP",
                risk_score=20.0,
                attributes={"hop_url": hop_url}
            )
            eg.add_edge(last_id, hop_id, relationship="REDIRECTS_TO", risk_weight=20.0)
            last_id = hop_id

        final_url = url_result.get("final_url", root_url)
        landing_id = f"landing_{uuid.uuid4().hex[:8]}"
        status = url_result.get("destination_status", "ACTIVE")
        eg.add_node(
            landing_id,
            label=f"Landing: {url_result.get('domain', 'destination')}",
            node_type="LANDING_PAGE",
            risk_score=u_risk,
            attributes={
                "final_url": final_url,
                "destination_status": status,
                "evasion_technique": url_result.get("evasion_technique", None)
            }
        )
        eg.add_edge(last_id, landing_id, relationship="RESOLVES_TO_LANDING", risk_weight=u_risk)

        if u_risk >= 50.0:
            action_id = f"action_{uuid.uuid4().hex[:8]}"
            eg.add_node(
                action_id,
                label="Action: Harvest Credentials",
                node_type="REQUESTED_ACTION",
                risk_score=85.0,
                attributes={"action": "Credential Harvesting Pretext"}
            )
            eg.add_edge(landing_id, action_id, relationship="REQUESTS_ACTION", risk_weight=85.0)

        return eg
