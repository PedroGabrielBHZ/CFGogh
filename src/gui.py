#!/usr/bin/env python3
"""
CFGogh GUI - Tkinter interface for the Smart Contract CFG Analyzer
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import threading
from PIL import Image, ImageTk
import subprocess
from cfg_generator import CFGGenerator
from visualizer import Visualizer
from taint_analyzer import TaintAnalyzer


class CFGoghGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CFGogh - Smart Contract CFG Analyzer")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")

        # Variables
        self.contract_file = tk.StringVar()
        self.output_file = tk.StringVar(value="output.dot")
        self.taint_analysis = tk.BooleanVar()
        self.generate_report = tk.BooleanVar()
        self.render_visualization = tk.BooleanVar(value=True)

        # Analysis results
        self.analysis_running = False
        self.last_rendered_image = None

        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(7, weight=1)

        # Title
        title_label = ttk.Label(
            main_frame,
            text="CFGogh - Smart Contract CFG Analyzer",
            font=("Arial", 16, "bold"),
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # File selection section
        file_frame = ttk.LabelFrame(main_frame, text="Contract File", padding="10")
        file_frame.grid(
            row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )
        file_frame.columnconfigure(1, weight=1)

        ttk.Label(file_frame, text="Solidity Contract:").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 10)
        )

        file_entry = ttk.Entry(file_frame, textvariable=self.contract_file, width=50)
        file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        browse_btn = ttk.Button(file_frame, text="Browse...", command=self.browse_file)
        browse_btn.grid(row=0, column=2)

        # Output settings section
        output_frame = ttk.LabelFrame(main_frame, text="Output Settings", padding="10")
        output_frame.grid(
            row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )
        output_frame.columnconfigure(1, weight=1)

        ttk.Label(output_frame, text="Output File:").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 10)
        )

        output_entry = ttk.Entry(output_frame, textvariable=self.output_file, width=50)
        output_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # Analysis options section
        options_frame = ttk.LabelFrame(
            main_frame, text="Analysis Options", padding="10"
        )
        options_frame.grid(
            row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )

        ttk.Checkbutton(
            options_frame, text="Perform Taint Analysis", variable=self.taint_analysis
        ).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))

        ttk.Checkbutton(
            options_frame,
            text="Generate Analysis Report",
            variable=self.generate_report,
        ).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))

        ttk.Checkbutton(
            options_frame,
            text="Render Visualization",
            variable=self.render_visualization,
        ).grid(row=0, column=2, sticky=tk.W)

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=4, column=0, columnspan=3, pady=10)

        self.analyze_btn = ttk.Button(
            control_frame,
            text="Analyze Contract",
            command=self.run_analysis,
            style="Accent.TButton",
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.clear_btn = ttk.Button(
            control_frame, text="Clear Results", command=self.clear_results
        )
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.open_output_btn = ttk.Button(
            control_frame, text="Open Output Folder", command=self.open_output_folder
        )
        self.open_output_btn.pack(side=tk.LEFT)

        # Progress bar
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_label = ttk.Label(main_frame, textvariable=self.progress_var)
        self.progress_label.grid(row=5, column=0, columnspan=3, pady=(10, 5))

        self.progress_bar = ttk.Progressbar(main_frame, mode="indeterminate")
        self.progress_bar.grid(
            row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )

        # Results section with notebook (tabs)
        results_frame = ttk.LabelFrame(
            main_frame, text="Analysis Results", padding="10"
        )
        results_frame.grid(
            row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10)
        )
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Visualization tab
        self.viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.viz_frame, text="Visualization")

        # Create canvas for image with scrollbars
        self.canvas_frame = ttk.Frame(self.viz_frame)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True)

        self.image_canvas = tk.Canvas(self.canvas_frame, bg="white")
        v_scrollbar = ttk.Scrollbar(
            self.canvas_frame, orient=tk.VERTICAL, command=self.image_canvas.yview
        )
        h_scrollbar = ttk.Scrollbar(
            self.canvas_frame, orient=tk.HORIZONTAL, command=self.image_canvas.xview
        )
        self.image_canvas.configure(
            yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set
        )

        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.image_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Analysis report tab
        self.report_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.report_frame, text="Analysis Report")

        self.analysis_text = scrolledtext.ScrolledText(
            self.report_frame, wrap=tk.WORD, width=80, height=20
        )
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Vulnerability report tab
        self.vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vuln_frame, text="Vulnerability Report")

        self.vuln_text = scrolledtext.ScrolledText(
            self.vuln_frame, wrap=tk.WORD, width=80, height=20
        )
        self.vuln_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Console output tab
        self.console_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.console_frame, text="Console Output")

        self.console_text = scrolledtext.ScrolledText(
            self.console_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            bg="black",
            fg="green",
            font=("Courier", 10),
        )
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status bar
        self.status_var = tk.StringVar(value="Ready to analyze smart contracts")
        status_bar = ttk.Label(
            main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        )
        status_bar.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))

    def browse_file(self):
        """Open file dialog to select Solidity contract"""
        filename = filedialog.askopenfilename(
            title="Select Solidity Contract",
            filetypes=[("Solidity files", "*.sol"), ("All files", "*.*")],
        )
        if filename:
            self.contract_file.set(filename)
            # Auto-set output filename based on contract name
            contract_name = os.path.splitext(os.path.basename(filename))[0]
            self.output_file.set(f"{contract_name}_analysis.dot")

    def log_to_console(self, message):
        """Add message to console output"""
        self.console_text.insert(tk.END, message + "\n")
        self.console_text.see(tk.END)
        self.root.update_idletasks()

    def update_progress(self, message):
        """Update progress label"""
        self.progress_var.set(message)
        self.root.update_idletasks()

    def run_analysis(self):
        """Run the CFG analysis in a separate thread"""
        if self.analysis_running:
            return

        if not self.contract_file.get():
            messagebox.showerror("Error", "Please select a Solidity contract file")
            return

        if not os.path.exists(self.contract_file.get()):
            messagebox.showerror("Error", "Selected contract file does not exist")
            return

        # Disable the analyze button and start progress
        self.analyze_btn.config(state="disabled")
        self.progress_bar.start()
        self.analysis_running = True

        # Clear previous results
        self.clear_results()

        # Run analysis in separate thread to avoid freezing UI
        thread = threading.Thread(target=self.perform_analysis)
        thread.daemon = True
        thread.start()

    def perform_analysis(self):
        """Perform the actual analysis"""
        try:
            contract_path = self.contract_file.get()
            output_file = self.output_file.get()

            # Ensure output directory exists
            os.makedirs("output", exist_ok=True)
            if not output_file.startswith("output/"):
                output_path = os.path.join("output", output_file)
            else:
                output_path = output_file

            self.update_progress("Generating CFG...")
            self.log_to_console(f"=== CFGogh Analysis Started ===")
            self.log_to_console(f"Contract: {contract_path}")
            self.log_to_console(f"Output: {output_path}")

            # Generate CFG
            cfg_generator = CFGGenerator()
            result = cfg_generator.generate_cfg(contract_path, output_path)

            if result is None:
                self.log_to_console("Failed to generate CFG.")
                self.update_progress("Analysis failed")
                messagebox.showerror(
                    "Error", "Failed to generate CFG. Check console for details."
                )
                return

            self.log_to_console(
                f"CFG successfully generated and saved to: {output_path}"
            )

            # Initialize visualizer
            visualizer = Visualizer()

            # Generate analysis report
            if self.generate_report.get():
                self.update_progress("Generating analysis report...")
                self.log_to_console("Generating analysis report...")
                visualizer.create_summary_report(result)

                # Load and display analysis report
                report_path = os.path.join(visualizer.output_dir, "analysis_report.txt")
                if os.path.exists(report_path):
                    with open(report_path, "r") as f:
                        report_content = f.read()
                    self.root.after(
                        0, lambda: self.analysis_text.insert(tk.END, report_content)
                    )

            # Perform taint analysis
            tainted_flows = []
            if self.taint_analysis.get():
                self.update_progress("Performing taint analysis...")
                self.log_to_console("Performing taint analysis...")
                taint_analyzer = TaintAnalyzer()
                tainted_flows = taint_analyzer.identify_tainted_flows(result)

                vulnerability_report = taint_analyzer.generate_vulnerability_report()
                self.log_to_console("Taint analysis completed.")

                # Display vulnerability report in GUI
                self.root.after(
                    0, lambda: self.vuln_text.insert(tk.END, vulnerability_report)
                )

                # Save vulnerability report
                vuln_report_path = os.path.join(
                    visualizer.output_dir, "vulnerability_report.txt"
                )
                os.makedirs(visualizer.output_dir, exist_ok=True)
                with open(vuln_report_path, "w") as f:
                    f.write(vulnerability_report)
                self.log_to_console(
                    f"Vulnerability report saved to: {vuln_report_path}"
                )

            # Render visualization
            if self.render_visualization.get():
                self.update_progress("Rendering visualization...")
                self.log_to_console("Rendering CFG visualization...")

                rendered_file = None

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

                    self.log_to_console(
                        f"Highlighted DOT file saved to: {highlighted_path}"
                    )

                    # Render highlighted version
                    rendered_file = visualizer.render_dot_file(
                        highlighted_path, output_format="png"
                    )
                else:
                    # Render normal version
                    rendered_file = visualizer.render_dot_file(
                        output_path, output_format="png"
                    )

                if rendered_file:
                    self.log_to_console(f"Visualization saved to: {rendered_file}")
                    # Load and display the image
                    self.root.after(
                        0, lambda: self.load_and_display_image(rendered_file)
                    )

            self.update_progress("Analysis completed successfully")
            self.log_to_console("=== Analysis Completed ===")
            self.root.after(
                0, lambda: self.status_var.set("Analysis completed successfully")
            )

        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            self.log_to_console(error_msg)
            self.update_progress("Analysis failed")
            self.root.after(0, lambda: messagebox.showerror("Error", error_msg))

        finally:
            # Re-enable the analyze button and stop progress
            self.analysis_running = False
            self.root.after(0, lambda: self.analyze_btn.config(state="normal"))
            self.root.after(0, lambda: self.progress_bar.stop())

    def load_and_display_image(self, image_path):
        """Load and display the rendered CFG image"""
        try:
            if os.path.exists(image_path):
                # Load image with PIL
                pil_image = Image.open(image_path)

                # Convert to PhotoImage for tkinter
                photo = ImageTk.PhotoImage(pil_image)

                # Clear canvas
                self.image_canvas.delete("all")

                # Add image to canvas
                self.image_canvas.create_image(0, 0, anchor=tk.NW, image=photo)

                # Update scroll region
                self.image_canvas.configure(scrollregion=self.image_canvas.bbox("all"))

                # Keep a reference to prevent garbage collection
                self.last_rendered_image = photo

                # Switch to visualization tab
                self.notebook.select(self.viz_frame)

        except Exception as e:
            self.log_to_console(f"Error loading image: {str(e)}")

    def clear_results(self):
        """Clear all analysis results"""
        self.analysis_text.delete(1.0, tk.END)
        self.vuln_text.delete(1.0, tk.END)
        self.console_text.delete(1.0, tk.END)
        self.image_canvas.delete("all")
        self.last_rendered_image = None
        self.status_var.set("Results cleared")

    def open_output_folder(self):
        """Open the output folder in file manager"""
        output_dir = os.path.abspath("output")
        if os.path.exists(output_dir):
            if sys.platform == "win32":
                os.startfile(output_dir)
            elif sys.platform == "darwin":
                subprocess.run(["open", output_dir])
            else:
                subprocess.run(["xdg-open", output_dir])
        else:
            messagebox.showinfo(
                "Info", "Output folder does not exist yet. Run an analysis first."
            )


def main():
    """Main function to run the GUI"""
    root = tk.Tk()

    # Configure style
    style = ttk.Style()
    style.theme_use("clam")  # Use a modern theme

    app = CFGoghGUI(root)

    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_width()) // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f"+{x}+{y}")

    root.mainloop()


if __name__ == "__main__":
    main()
