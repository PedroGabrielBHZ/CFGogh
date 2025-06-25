class TaintAnalyzer:
    def __init__(self):
        self.vulnerabilities = []

    def identify_tainted_flows(self, analysis_result):
        """
        Analyze CFG to identify tainted flows and potential vulnerabilities
        """
        tainted_flows = []

        if "contracts" not in analysis_result:
            return tainted_flows

        # Store node mapping for global IDs
        self.node_mapping = analysis_result.get("node_mapping", {})

        for contract in analysis_result["contracts"]:
            for function in contract.functions:
                if not function.nodes:
                    continue

                # Analyze for reentrancy vulnerability
                reentrancy_flows = self._detect_reentrancy_vulnerability(function)
                if reentrancy_flows:
                    tainted_flows.extend(reentrancy_flows)

                # TODO: Add other vulnerability patterns
                # - Integer overflow/underflow
                # - Unchecked external calls
                # - Timestamp dependence
                # etc.

        return tainted_flows

    def _detect_reentrancy_vulnerability(self, function):
        """
        Detect reentrancy vulnerability pattern:
        External call followed by state change
        """
        vulnerabilities = []
        external_call_nodes = []
        state_change_nodes = []

        # Find external calls and state changes
        for i, node in enumerate(function.nodes):
            if node.expression:
                expr_str = str(node.expression)

                # Check for external calls (more specific detection)
                if any(call in expr_str for call in [".call{", ".send(", ".transfer("]):
                    external_call_nodes.append(
                        {
                            "index": i,
                            "node": node,
                            "expression": expr_str,
                            "type": "external_call",
                            "global_id": self.node_mapping.get(
                                node, i
                            ),  # Get global node ID
                        }
                    )

                # Check for state changes (storage writes) - exclude require statements
                if (
                    any(op in expr_str for op in ["+=", "-="])
                    and any(
                        storage_indicator in expr_str
                        for storage_indicator in ["balances", "mapping", "["]
                    )
                    and not expr_str.strip().startswith("require")
                ):

                    state_change_nodes.append(
                        {
                            "index": i,
                            "node": node,
                            "expression": expr_str,
                            "type": "state_change",
                            "global_id": self.node_mapping.get(
                                node, i
                            ),  # Get global node ID
                        }
                    )

        # Check for reentrancy pattern: external call before state change
        for ext_call in external_call_nodes:
            for state_change in state_change_nodes:
                if ext_call["index"] < state_change["index"]:
                    # Potential reentrancy vulnerability
                    vulnerability = {
                        "type": "reentrancy",
                        "severity": "HIGH",
                        "function": function.canonical_name,
                        "description": f"External call at node {ext_call['index']} before state change at node {state_change['index']}",
                        "external_call": ext_call,
                        "state_change": state_change,
                        "tainted_nodes": [
                            ext_call.get("global_id", ext_call["index"]),
                            state_change.get("global_id", state_change["index"]),
                        ],
                    }
                    vulnerabilities.append(vulnerability)
                    self.vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _detect_unchecked_external_calls(self, function):
        """
        Detect unchecked external calls
        """
        # TODO: Implement detection for unchecked external calls
        pass

    def _detect_integer_overflow(self, function):
        """
        Detect potential integer overflow/underflow
        """
        # TODO: Implement detection for integer overflow
        pass

    def generate_vulnerability_report(self):
        """
        Generate a detailed vulnerability report
        """
        if not self.vulnerabilities:
            return "No vulnerabilities detected."

        report_lines = []
        report_lines.append("=== Vulnerability Analysis Report ===")
        report_lines.append("")

        for i, vuln in enumerate(self.vulnerabilities, 1):
            report_lines.append(f"Vulnerability #{i}")
            report_lines.append(f"Type: {vuln['type'].upper()}")
            report_lines.append(f"Severity: {vuln['severity']}")
            report_lines.append(f"Function: {vuln['function']}")
            report_lines.append(f"Description: {vuln['description']}")

            if vuln["type"] == "reentrancy":
                report_lines.append(
                    f"External Call: {vuln['external_call']['expression']}"
                )
                report_lines.append(
                    f"State Change: {vuln['state_change']['expression']}"
                )
                report_lines.append(
                    "Recommendation: Move state changes before external calls"
                )

            report_lines.append("-" * 50)
            report_lines.append("")

        return "\n".join(report_lines)
