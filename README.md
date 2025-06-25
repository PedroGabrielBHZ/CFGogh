# CFGogh - Smart Contract CFG Analyzer

## Overview
CFGogh is a powerful command-line interface (CLI) tool that leverages Slither to generate and analyze Control Flow Graphs (CFG) of Solidity smart contracts. It identifies security vulnerabilities through taint flow analysis and provides visual representations with highlighted vulnerable paths.

## Features
- **CFG Generation**: Generate comprehensive Control Flow Graphs in .dot format from smart contracts
- **Vulnerability Detection**: Identify security vulnerabilities including:
  - Reentrancy attacks
  - External call patterns
  - State change ordering issues
- **Taint Flow Analysis**: Track data flows and identify potentially dangerous execution paths
- **Visual Highlighting**: Color-code vulnerable nodes in the CFG for easy identification
- **Detailed Reporting**: Generate comprehensive analysis reports with severity levels and recommendations
- **Multiple Output Formats**: Support for .dot files and PNG images (with Graphviz)

## Installation

### Prerequisites
- Python 3.8 or higher
- Node.js (for Solidity compilation)
- Graphviz (optional, for PNG rendering)

### Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd CFGogh
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\Activate.ps1
   # On Linux/Mac:
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. (Optional) Install Graphviz for image rendering:
   - Windows: Download from https://graphviz.org/download/
   - Ubuntu: `sudo apt-get install graphviz`
   - macOS: `brew install graphviz`

## Usage

### Basic CFG Generation
Generate a Control Flow Graph from a smart contract:
```bash
python src/main.py path/to/contract.sol
```

### Advanced Analysis Options
```bash
# Generate CFG with custom output file
python src/main.py contract.sol --output my_analysis.dot

# Perform taint analysis to detect vulnerabilities
python src/main.py contract.sol --taint

# Generate analysis report
python src/main.py contract.sol --report

# Render visualization (requires Graphviz)
python src/main.py contract.sol --render

# Complete analysis with all features
python src/main.py contract.sol --taint --report --render --output complete_analysis.dot
```

### Command Line Options
- `contract`: Path to the Solidity smart contract file (required)
- `--output`: Specify output .dot file name (default: output.dot)
- `--taint`: Perform taint analysis for vulnerability detection
- `--report`: Generate detailed analysis report
- `--render`: Create PNG visualization (requires Graphviz)

## Example Analysis

### 1. Analyze a Contract for Reentrancy Vulnerabilities
```bash
python src/main.py test_contracts/reentrancy_vulnerable.sol --taint --report
```

**Sample Output:**
```
=== CFGogh - Smart Contract CFG Analyzer ===
Contract: test_contracts/reentrancy_vulnerable.sol

Found 1 contracts
Contract: ReentrancyVulnerable
  Function: withdraw (7 nodes)
  Function: withdrawSafe (7 nodes)

=== Vulnerability Analysis Report ===

Vulnerability #1
Type: REENTRANCY
Severity: HIGH
Function: ReentrancyVulnerable.withdraw(uint256)
Description: External call at node 3 before state change at node 5
External Call: (success,None) = msg.sender.call{value: amount}()
State Change: balances[msg.sender] -= amount
Recommendation: Move state changes before external calls
```

### 2. Generate Visual CFG with Highlighted Vulnerabilities
```bash
python src/main.py contract.sol --taint --render
```

This creates:
- `output.dot`: Original CFG
- `output_highlighted.dot`: CFG with vulnerable nodes highlighted in red
- `output/output.png`: Visual representation (if Graphviz is installed)

## Output Files

CFGogh generates several output files:

- **CFG File** (`*.dot`): GraphViz format showing the complete control flow
- **Highlighted CFG** (`*_highlighted.dot`): Same CFG with vulnerable nodes highlighted
- **Analysis Report** (`output/analysis_report.txt`): Detailed breakdown of functions and calls
- **Vulnerability Report** (`output/vulnerability_report.txt`): Security findings with recommendations
- **Visual Graph** (`output/*.png`): Image representation of the CFG

## Understanding the Output

### Node Colors in CFG
- **Light Green**: Entry points (function start)
- **Light Coral**: Return points (function end)
- **Yellow**: Require/Assert statements
- **Orange**: External calls or state changes
- **Red**: Vulnerable nodes (when using --taint)
- **Light Blue**: Other operations

### Vulnerability Detection
CFGogh currently detects:
- **Reentrancy**: External calls before state changes
- More vulnerability patterns coming soon...

## Project Structure
```
CFGogh/
├── src/
│   ├── main.py              # CLI entry point
│   ├── cfg_generator.py     # CFG generation using Slither
│   ├── taint_analyzer.py    # Vulnerability detection
│   └── visualizer.py        # Report generation and highlighting
├── test_contracts/          # Example contracts for testing
├── output/                  # Generated reports and visualizations
├── requirements.txt         # Python dependencies
├── setup.py                # Package configuration
└── README.md               # This file
```

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run the tool on test contracts to verify functionality
5. Submit a pull request

### Adding New Vulnerability Patterns
To add new vulnerability detection patterns:
1. Extend the `TaintAnalyzer` class in `src/taint_analyzer.py`
2. Add detection logic in the `identify_tainted_flows` method
3. Update the vulnerability report generation
4. Add test cases

## Troubleshooting

### Common Issues
1. **"slither command not found"**: Ensure Slither is installed via `pip install slither-analyzer`
2. **"failed to execute dot"**: Install Graphviz for visualization features
3. **"No module named 'slither'"**: Activate your virtual environment
4. **Compilation errors**: Ensure your Solidity contract syntax is valid

### Getting Help
- Check the [Issues](https://github.com/your-repo/issues) page for known problems
- Create a new issue with your contract and error details
- Include the full command and output when reporting bugs

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Acknowledgments
- Built on top of [Slither](https://github.com/crytic/slither) by Trail of Bits
- Inspired by the need for better smart contract security analysis tools
- Thanks to the Ethereum security research community

---

**CFGogh** - *Making smart contract vulnerabilities as visible as Van Gogh's brushstrokes*