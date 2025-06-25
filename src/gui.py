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
from solc_manager import SolcManager


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

        # Solidity compiler manager
        self.solc_manager = SolcManager()

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
        main_frame.rowconfigure(8, weight=1)

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

        # Solidity Version Management section
        solc_frame = ttk.LabelFrame(main_frame, text="Solidity Compiler", padding="10")
        solc_frame.grid(
            row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )
        solc_frame.columnconfigure(1, weight=1)

        # Current version display
        ttk.Label(solc_frame, text="Current Version:").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 10)
        )

        self.current_version_var = tk.StringVar(value="Checking...")
        self.version_label = ttk.Label(
            solc_frame, textvariable=self.current_version_var
        )
        self.version_label.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))

        # Version selection and management
        version_control_frame = ttk.Frame(solc_frame)
        version_control_frame.grid(
            row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0)
        )

        ttk.Label(version_control_frame, text="Version:").pack(
            side=tk.LEFT, padx=(0, 5)
        )

        self.version_combo = ttk.Combobox(
            version_control_frame, width=15, state="readonly"
        )
        self.version_combo.pack(side=tk.LEFT, padx=(0, 10))

        self.install_btn = ttk.Button(
            version_control_frame, text="Install", command=self.install_version
        )
        self.install_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.use_btn = ttk.Button(
            version_control_frame, text="Use", command=self.use_version
        )
        self.use_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.auto_btn = ttk.Button(
            version_control_frame, text="Auto-detect", command=self.auto_detect_version
        )
        self.auto_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.refresh_btn = ttk.Button(
            version_control_frame, text="Refresh", command=self.refresh_versions
        )
        self.refresh_btn.pack(side=tk.LEFT)

        # Output settings section
        output_frame = ttk.LabelFrame(main_frame, text="Output Settings", padding="10")
        output_frame.grid(
            row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
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
            row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
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
        control_frame.grid(row=5, column=0, columnspan=3, pady=10)

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
        self.progress_label.grid(row=6, column=0, columnspan=3, pady=(10, 5))

        self.progress_bar = ttk.Progressbar(main_frame, mode="indeterminate")
        self.progress_bar.grid(
            row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10)
        )

        # Results section with notebook (tabs)
        results_frame = ttk.LabelFrame(
            main_frame, text="Analysis Results", padding="10"
        )
        results_frame.grid(
            row=8, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10)
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
        status_bar.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))

        # Initialize Solidity version info
        self.refresh_versions()

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

    def refresh_versions(self):
        """Refresh Solidity version information"""

        def refresh_in_thread():
            try:
                # Check if solc-select is available
                if not self.solc_manager.is_solc_select_available():
                    self.root.after(
                        0, lambda: self.current_version_var.set("solc-select not found")
                    )
                    self.root.after(
                        0, lambda: self.version_combo.configure(state="disabled")
                    )
                    self.root.after(
                        0, lambda: self.install_btn.configure(state="disabled")
                    )
                    self.root.after(0, lambda: self.use_btn.configure(state="disabled"))
                    self.root.after(
                        0, lambda: self.auto_btn.configure(state="disabled")
                    )
                    return

                # Get current version
                current = self.solc_manager.get_current_version()
                current_text = current if current else "Not set"
                current_text_copy = current_text  # Make a copy for lambda
                self.root.after(
                    0, lambda text=current_text_copy: self.current_version_var.set(text)
                )

                # Get available versions (combine installed and some common ones)
                installed = self.solc_manager.get_installed_versions()

                # Add some common versions that might not be installed
                common_versions = [
                    "0.8.19",
                    "0.8.20",
                    "0.8.21",
                    "0.8.22",
                    "0.8.23",
                    "0.8.24",
                    "0.8.25",
                    "0.8.26",
                    "0.7.6",
                    "0.6.12",
                    "0.5.17",
                    "0.4.25",
                ]
                all_versions = list(set(installed + common_versions))

                # Safe version sorting - filter out invalid versions first
                def safe_version_sort(version_str):
                    try:
                        # Only process valid version strings with dots
                        if not version_str or "." not in version_str:
                            return [0, 0, 0]  # Default for invalid versions
                        parts = version_str.split(".")
                        # Convert each part to int, default to 0 if conversion fails
                        return [
                            int(part) if part.isdigit() else 0 for part in parts[:3]
                        ]
                    except:
                        return [0, 0, 0]

                # Filter out empty/invalid versions and sort
                valid_versions = [v for v in all_versions if v and "." in v]
                valid_versions.sort(key=safe_version_sort, reverse=True)

                all_versions_copy = valid_versions.copy()  # Make a copy for lambda
                self.root.after(
                    0,
                    lambda versions=all_versions_copy: self.version_combo.configure(
                        values=versions
                    ),
                )
                if current in valid_versions:
                    current_copy = current  # Make a copy for lambda
                    self.root.after(0, lambda c=current_copy: self.version_combo.set(c))
                elif valid_versions:
                    first_version = valid_versions[0]  # Make a copy for lambda
                    self.root.after(
                        0, lambda v=first_version: self.version_combo.set(v)
                    )

            except Exception as e:
                error_msg = f"Error: {str(e)}"
                self.root.after(
                    0, lambda msg=error_msg: self.current_version_var.set(msg)
                )

        # Run in background thread to avoid blocking UI
        thread = threading.Thread(target=refresh_in_thread)
        thread.daemon = True
        thread.start()

    def install_version(self):
        """Install the selected Solidity version"""
        version = self.version_combo.get()
        if not version:
            messagebox.showwarning("Warning", "Please select a version to install")
            return

        def install_in_thread():
            self.root.after(0, lambda: self.install_btn.configure(state="disabled"))
            version_copy = version  # Make a copy for lambda
            self.root.after(
                0,
                lambda v=version_copy: self.log_to_console(
                    f"Installing Solidity {v}..."
                ),
            )

            success, message = self.solc_manager.install_version(version)

            message_copy = message  # Make a copy for lambda
            self.root.after(0, lambda msg=message_copy: self.log_to_console(msg))
            if success:
                self.root.after(0, lambda: self.refresh_versions())
                success_msg = message  # Make a copy for lambda
                self.root.after(
                    0, lambda msg=success_msg: messagebox.showinfo("Success", msg)
                )
            else:
                error_msg = message  # Make a copy for lambda
                self.root.after(
                    0, lambda msg=error_msg: messagebox.showerror("Error", msg)
                )

            self.root.after(0, lambda: self.install_btn.configure(state="normal"))

        thread = threading.Thread(target=install_in_thread)
        thread.daemon = True
        thread.start()

    def use_version(self):
        """Use the selected Solidity version"""
        version = self.version_combo.get()
        if not version:
            messagebox.showwarning("Warning", "Please select a version to use")
            return

        def use_in_thread():
            self.root.after(0, lambda: self.use_btn.configure(state="disabled"))
            version_copy = version  # Make a copy for lambda
            self.root.after(
                0,
                lambda v=version_copy: self.log_to_console(
                    f"Switching to Solidity {v}..."
                ),
            )

            success, message = self.solc_manager.use_version(version)

            message_copy = message  # Make a copy for lambda
            self.root.after(0, lambda msg=message_copy: self.log_to_console(msg))

            if success:
                # Immediately update the current version label synchronously
                current_version = self.solc_manager.get_current_version()
                current_text = current_version if current_version else "Not set"
                self.root.after(
                    0, lambda text=current_text: self.current_version_var.set(text)
                )

                # Also refresh all versions asynchronously (for completeness)
                self.root.after(100, lambda: self.refresh_versions())

                success_msg = message  # Make a copy for lambda
                self.root.after(
                    0, lambda msg=success_msg: messagebox.showinfo("Success", msg)
                )
            else:
                error_msg = message  # Make a copy for lambda
                self.root.after(
                    0, lambda msg=error_msg: messagebox.showerror("Error", msg)
                )

            self.root.after(0, lambda: self.use_btn.configure(state="normal"))

        thread = threading.Thread(target=use_in_thread)
        thread.daemon = True
        thread.start()

    def auto_detect_version(self):
        """Auto-detect and install/use the required Solidity version for the selected contract"""
        contract_path = self.contract_file.get()
        if not contract_path:
            messagebox.showwarning("Warning", "Please select a contract file first")
            return

        def auto_detect_in_thread():
            self.root.after(0, lambda: self.auto_btn.configure(state="disabled"))
            self.root.after(
                0, lambda: self.log_to_console("Auto-detecting Solidity version...")
            )

            success, message = self.solc_manager.auto_install_for_contract(
                contract_path
            )

            message_copy = message  # Make a copy for lambda
            self.root.after(0, lambda msg=message_copy: self.log_to_console(msg))

            if success:
                # Immediately update the current version label synchronously
                current_version = self.solc_manager.get_current_version()
                current_text = current_version if current_version else "Not set"
                self.root.after(
                    0, lambda text=current_text: self.current_version_var.set(text)
                )

                # Also refresh all versions asynchronously (for completeness)
                self.root.after(100, lambda: self.refresh_versions())

                success_msg = message  # Make a copy for lambda
                self.root.after(
                    0, lambda msg=success_msg: messagebox.showinfo("Success", msg)
                )
            else:
                error_msg = message  # Make a copy for lambda
                self.root.after(
                    0, lambda msg=error_msg: messagebox.showerror("Error", msg)
                )

            self.root.after(0, lambda: self.auto_btn.configure(state="normal"))

        thread = threading.Thread(target=auto_detect_in_thread)
        thread.daemon = True
        thread.start()

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

            self.update_progress("Checking Solidity version...")
            self.log_to_console(f"=== CFGogh Analysis Started ===")
            self.log_to_console(f"Contract: {contract_path}")
            self.log_to_console(f"Output: {output_path}")

            # Check if contract requires a different Solidity version
            required_version = self.solc_manager.extract_pragma_version(contract_path)
            current_version = self.solc_manager.get_current_version()

            if required_version and current_version != required_version:
                self.log_to_console(
                    f"Contract requires Solidity {required_version}, current version is {current_version}"
                )
                self.log_to_console(
                    "Consider using the Auto-detect button to install the correct version"
                )
            elif required_version:
                self.log_to_console(
                    f"Using Solidity {current_version} (matches contract requirement)"
                )
            else:
                self.log_to_console(
                    f"Using Solidity {current_version} (no version requirement detected)"
                )

            self.update_progress("Generating CFG...")
            self.log_to_console("Generating Control Flow Graph...")

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
