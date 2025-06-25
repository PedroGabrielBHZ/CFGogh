import os
import graphviz
from pathlib import Path


class Visualizer:
    def __init__(self):
        self.output_dir = "output"

    def render_dot_file(self, dot_file_path, output_format="png", view=False):
        """
        Render a DOT file to an image using graphviz
        """
        try:
            # Ensure output directory exists
            Path(self.output_dir).mkdir(exist_ok=True)

            # Read the DOT file
            with open(dot_file_path, "r") as f:
                dot_content = f.read()

            # Create graphviz source
            source = graphviz.Source(dot_content)

            # Generate output filename
            base_name = Path(dot_file_path).stem
            output_path = os.path.join(self.output_dir, base_name)

            # Render the graph
            rendered_file = source.render(
                output_path, format=output_format, cleanup=True
            )

            print(f"CFG visualization rendered: {rendered_file}")

            if view:
                source.view(output_path, cleanup=True)

            return rendered_file

        except Exception as e:
            print(f"Error rendering CFG: {str(e)}")
            print("Note: This requires Graphviz to be installed on your system.")
            print("You can install it from: https://graphviz.org/download/")
            return None

    def highlight_tainted_flows(self, dot_content, tainted_nodes):
        """
        Modify DOT content to highlight tainted flows
        """
        lines = dot_content.split("\n")
        highlighted_lines = []

        for line in lines:
            # Check if this line defines a node that should be highlighted
            for node_id in tainted_nodes:
                if f"{node_id} [" in line and "fillcolor=" in line:
                    # Change the color to red for tainted nodes
                    line = line.replace("fillcolor=lightblue", "fillcolor=red")
                    line = line.replace("fillcolor=orange", "fillcolor=red")
                    line = line.replace("fillcolor=yellow", "fillcolor=red")
                    break
            highlighted_lines.append(line)

        return "\n".join(highlighted_lines)

    def create_summary_report(self, analysis_result):
        """
        Create a text summary of the CFG analysis
        """
        try:
            report_lines = []
            report_lines.append("=== CFGogh Analysis Report ===")
            report_lines.append("")

            if "contracts" in analysis_result:
                for contract in analysis_result["contracts"]:
                    report_lines.append(f"Contract: {contract.name}")
                    report_lines.append("-" * (len(contract.name) + 10))

                    for function in contract.functions:
                        if function.nodes:
                            report_lines.append(f"  Function: {function.name}")
                            report_lines.append(f"    Nodes: {len(function.nodes)}")

                            # Look for external calls
                            external_calls = []
                            state_changes = []

                            for i, node in enumerate(function.nodes):
                                if node.expression:
                                    expr_str = str(node.expression)
                                    if any(
                                        call in expr_str.lower()
                                        for call in ["call", "send", "transfer"]
                                    ):
                                        external_calls.append(f"Node {i}: {expr_str}")
                                    if any(op in expr_str for op in ["+=", "-=", "="]):
                                        state_changes.append(f"Node {i}: {expr_str}")

                            if external_calls:
                                report_lines.append("    External calls:")
                                for call in external_calls:
                                    report_lines.append(f"      {call}")

                            if state_changes:
                                report_lines.append("    State changes:")
                                for change in state_changes:
                                    report_lines.append(f"      {change}")

                            report_lines.append("")

            report_content = "\n".join(report_lines)

            # Save report
            report_path = os.path.join(self.output_dir, "analysis_report.txt")
            Path(self.output_dir).mkdir(exist_ok=True)

            with open(report_path, "w") as f:
                f.write(report_content)

            print(f"Analysis report saved: {report_path}")
            print("\n" + report_content)

            return report_path

        except Exception as e:
            print(f"Error creating summary report: {str(e)}")
            return None
