"""Validate documented participant access without claiming live solvability."""
import re


def access_check(plan, graph, prompt=""):
    nodes = {str(node["id"]): node for node in graph.get("nodes", [])}
    items = []
    for step in plan["steps"]:
        node = nodes.get(step["node_id"], {})
        solution = step.get("solution", "")
        # Only the procedure counts. Answer tables, internal paths and generic
        # hint text do not establish a participant access mechanism.
        match = re.search(r"### Access Instructions\s*(.*?)(?=\n### |\Z)", solution, re.S)
        procedure = match.group(1) if match else re.split(r"Facilitator|Expected flag|Current challenge answer|### Need a Hint", solution)[0]
        targets = [str(node.get(key) or "") for key in ("ipv4", "label", "name")]
        def mentions_target(value):
            return any(target and re.search(r"(?<![\w.-])" + re.escape(target) + r"(?![\w.-])", value) for target in targets)
        reviewed = prompt if mentions_target(prompt) and re.search(r"\b(curl|wget|ssh|nc|netcat|smbclient|ftp|msfconsole)\b", prompt) else ""
        text = procedure + "\n" + reviewed
        reasons = []
        if not node.get("ipv4"):
            reasons.append("No resolved participant target address")
        if re.search(r"\{\{[^}]+\}\}", text):
            reasons.append("Access procedure contains unresolved placeholders")
        if re.search(r"\bGET\s+/(?:tmp/vulns|opt/scenarioforge|flow_injects)/", text):
            reasons.append("GET uses a host/container file path; document the service-relative retrieval path")
        network = re.search(r"\b(curl|wget|ssh|nc|netcat|smbclient|ftp|msfconsole)\b", text)
        retrieval = re.search(r"\b(GET|cat|read|retrieve|download|fetch|curl|wget|exploit)\b", text, re.I)
        connection_target = network and mentions_target(text)
        if not network or not retrieval or not connection_target:
            reasons.append("No documented participant connection and retrieval procedure; provide the service endpoint or remote-shell/exploit access and artifact retrieval commands")
        # A local cat on a target container requires a documented shell entry.
        if re.search(r"\bcat\s+/flow_injects/", text) and not re.search(r"\b(ssh|exploit|msfconsole)\b", text, re.I):
            reasons.append("Container artifact retrieval requires a documented remote shell or exposed file endpoint")
        items.append(dict(name=step["title"], node_id=step["node_id"], step_id=step["id"],
                          status="fail" if reasons else "pass",
                          detail="; ".join(reasons) if reasons else "Documented connection and retrieval procedure present; live reachability and successful execution remain separate checks"))
    failed = sum(item["status"] == "fail" for item in items)
    return dict(key="challenge_access", label="Challenge participant access procedures", status="fail" if failed else "pass",
                summary=f"{failed} of {len(items)} challenge access procedures need review" if failed else f"{len(items)} challenge access procedures documented (static validation)",
                items=items)
