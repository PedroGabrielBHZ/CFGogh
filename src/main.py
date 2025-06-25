import argparse
import os
import sys
from cfg_generator import CFGGenerator
from visualizer import Visualizer
from taint_analyzer import TaintAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description="Analyze smart contracts for tainted flows."
    )
    parser.add_argument(
        "contract", type=str, nargs="?", help="Path to the smart contract file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output.dot",
        help="Output file for the CFG in .dot format",
    )
    parser.add_argument(
        "--render", action="store_true", help="Render the CFG to PNG image"
    )
    parser.add_argument(
        "--report", action="store_true", help="Generate analysis report"
    )
    parser.add_argument(
        "--taint",
        action="store_true",
        help="Perform taint analysis for vulnerabilities",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the graphical user interface",
    )
    args = parser.parse_args()

    # Launch GUI if requested
    if args.gui:
        try:
            from gui import main as gui_main

            gui_main()
            return 0
        except ImportError as e:
            print(f"Error: Failed to import GUI dependencies: {e}")
            print("Please install required dependencies: pip install Pillow")
            return 1

    # Require contract file for CLI mode
    if not args.contract:
        print(
            "Error: Contract file is required for CLI mode. Use --gui for graphical interface."
        )
        parser.print_help()
        return 1

    # Check if contract file exists
    if not os.path.exists(args.contract):
        print(f"Error: Contract file '{args.contract}' not found.")
        return 1

    # Ensure output directory exists and output file is in the output directory
    os.makedirs("output", exist_ok=True)
    if not args.output.startswith("output/"):
        output_path = os.path.join("output", args.output)
    else:
        output_path = args.output

    print("=== CFGogh - Smart Contract CFG Analyzer ===")
    print(f"Contract: {args.contract}")
    print(f"Output: {output_path}")
    print()

    # Generate CFG
    cfg_generator = CFGGenerator()
    result = cfg_generator.generate_cfg(args.contract, output_path)

    if result is None:
        print("Failed to generate CFG.")
        return 1

    print(f"\nCFG successfully generated and saved to: {output_path}")

    # Initialize visualizer
    visualizer = Visualizer()

    # Generate analysis report
    if args.report:
        visualizer.create_summary_report(result)

    # Perform taint analysis
    tainted_flows = []
    if args.taint:
        print("\nPerforming taint analysis...")
        taint_analyzer = TaintAnalyzer()
        tainted_flows = taint_analyzer.identify_tainted_flows(result)

        vulnerability_report = taint_analyzer.generate_vulnerability_report()
        print(vulnerability_report)

        # Save vulnerability report
        vuln_report_path = os.path.join(
            visualizer.output_dir, "vulnerability_report.txt"
        )
        os.makedirs(visualizer.output_dir, exist_ok=True)
        with open(vuln_report_path, "w") as f:
            f.write(vulnerability_report)
        print(f"Vulnerability report saved to: {vuln_report_path}")

    # Render visualization if requested
    if args.render:
        print("\nRendering CFG visualization...")

        # If we have tainted flows, create a highlighted version
        if tainted_flows:
            # Read original DOT content
            with open(output_path, "r") as f:
                dot_content = f.read()

            # Get all tainted node IDs
            all_tainted_nodes = []
            for flow in tainted_flows:
                if "tainted_nodes" in flow:
                    all_tainted_nodes.extend(flow["tainted_nodes"])

            # Create highlighted version
            highlighted_dot = visualizer.highlight_tainted_flows(
                dot_content, all_tainted_nodes
            )
            highlighted_path = output_path.replace(".dot", "_highlighted.dot")
            with open(highlighted_path, "w") as f:
                f.write(highlighted_dot)

            print(f"Highlighted DOT file saved to: {highlighted_path}")

            # Render highlighted version
            rendered_file = visualizer.render_dot_file(
                highlighted_path, output_format="png"
            )
        else:
            # Render normal version
            rendered_file = visualizer.render_dot_file(output_path, output_format="png")

        if rendered_file:
            print(f"Visualization saved to: {rendered_file}")

    return 0


if __name__ == "__main__":
    exit(main())
