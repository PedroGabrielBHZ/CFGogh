import os
from slither import Slither
from slither.core.cfg.node import Node


class CFGGenerator:
    def __init__(self):
        self.slither = None
        self.contracts = []
        self.functions = []

    def generate_cfg(self, contract_path, output_path="output.dot"):
        """
        Generate Control Flow Graph using Slither's Python API
        """
        try:
            print(f"Analyzing contract: {contract_path}")

            # Initialize Slither
            self.slither = Slither(contract_path)
            self.contracts = self.slither.contracts

            print(f"Found {len(self.contracts)} contracts")

            # Extract all functions from all contracts
            all_functions = []
            for contract in self.contracts:
                print(f"Contract: {contract.name}")
                for function in contract.functions:
                    if function.nodes:  # Only include functions that have nodes
                        all_functions.append(function)
                        print(
                            f"  Function: {function.name} ({len(function.nodes)} nodes)"
                        )

            # Generate DOT file for the CFG
            dot_content = self._generate_dot_file(all_functions)

            # Write to output file
            with open(output_path, "w") as f:
                f.write(dot_content)

            print(f"CFG generated successfully: {output_path}")
            return {
                "slither": self.slither,
                "contracts": self.contracts,
                "functions": all_functions,
                "dot_file": output_path,
                "node_mapping": self.node_mapping,  # Add node mapping to result
            }

        except Exception as e:
            print(f"Error generating CFG: {str(e)}")
            return None

    def _generate_dot_file(self, functions):
        """
        Generate DOT format representation of the CFG
        """
        dot_lines = ["digraph CFG {"]
        dot_lines.append("  rankdir=TB;")
        dot_lines.append("  node [shape=box, style=filled, fillcolor=lightblue];")
        dot_lines.append("")

        node_id = 0
        self.node_mapping = {}  # Store as instance variable

        for function in functions:
            # Add function header
            dot_lines.append(f"  subgraph cluster_{function.canonical_name} {{")
            dot_lines.append(f'    label="{function.canonical_name}";')
            dot_lines.append("    style=filled;")
            dot_lines.append("    fillcolor=lightgray;")
            dot_lines.append("")

            # Map nodes to IDs
            for node in function.nodes:
                self.node_mapping[node] = node_id
                node_id += 1

            # Add nodes
            for node in function.nodes:
                node_label = self._get_node_label(node)
                color = self._get_node_color(node)
                dot_lines.append(
                    f'    {self.node_mapping[node]} [label="{node_label}", fillcolor={color}];'
                )

            # Add edges
            for node in function.nodes:
                for son in node.sons:
                    if son in self.node_mapping:
                        dot_lines.append(
                            f"    {self.node_mapping[node]} -> {self.node_mapping[son]};"
                        )

            dot_lines.append("  }")
            dot_lines.append("")

        dot_lines.append("}")
        return "\n".join(dot_lines)

    def _get_node_label(self, node):
        """
        Get a readable label for a CFG node
        """
        if node.type.name == "ENTRYPOINT":
            return "ENTRY"
        elif node.type.name == "RETURN":
            return "RETURN"
        elif node.expression:
            expr_str = str(node.expression)
            # Limit length and escape quotes
            if len(expr_str) > 50:
                expr_str = expr_str[:47] + "..."
            return expr_str.replace('"', '\\"').replace("\n", "\\n")
        else:
            return f"{node.type.name}"

    def _get_node_color(self, node):
        """
        Get color for different node types
        """
        if node.type.name == "ENTRYPOINT":
            return "lightgreen"
        elif node.type.name == "RETURN":
            return "lightcoral"
        elif node.contains_require_or_assert():
            return "yellow"
        elif hasattr(node, "calls") and node.calls:
            return "orange"
        elif node.expression and any(
            call in str(node.expression).lower()
            for call in ["call", "send", "transfer"]
        ):
            return "orange"
        else:
            return "lightblue"
