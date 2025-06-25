#!/usr/bin/env python3
"""
Solidity Compiler Manager - Wrapper for solc-select functionality
"""

import subprocess
import re
import os
from typing import Optional, List, Tuple


class SolcManager:
    """Manager for Solidity compiler versions using solc-select"""

    def __init__(self):
        self.installed_versions = []
        self.current_version = None
        self._refresh_versions()

    def _run_command(self, command: List[str]) -> Tuple[bool, str]:
        """Run a command and return success status and output"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            return result.returncode == 0, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, f"Error running command: {str(e)}"

    def _refresh_versions(self):
        """Refresh the list of installed versions and current version"""
        # Get installed versions
        success, output = self._run_command(["solc-select", "versions"])
        if success:
            self.installed_versions = []
            for line in output.split("\n"):
                line = line.strip()
                if (
                    line
                    and not line.startswith("Available")
                    and not line.startswith("Installed")
                ):
                    # Extract just the version number using regex
                    match = re.search(r"(\d+\.\d+\.\d+)", line)
                    if match:
                        version = match.group(1)
                        self.installed_versions.append(version)
                        # Check if this is the current version
                        if "(current" in line.lower() or "*" in line:
                            self.current_version = version

    def get_current_version(self) -> Optional[str]:
        """Get the currently selected Solidity compiler version"""
        # solc-select doesn't have a 'version' command, so we get it from 'versions' output
        success, output = self._run_command(["solc-select", "versions"])
        if success:
            for line in output.split("\n"):
                line = line.strip()
                # Look for "(current, set by...)" pattern or "*" marker
                if "(current" in line.lower() or "*" in line:
                    # Extract version from line like "0.8.0 (current, set by ...)" or "* 0.8.0"
                    match = re.search(r"(\d+\.\d+\.\d+)", line)
                    if match:
                        self.current_version = match.group(1)
                        return self.current_version

        return None

    def get_installed_versions(self) -> List[str]:
        """Get list of installed Solidity compiler versions"""
        self._refresh_versions()
        return self.installed_versions.copy()

    def get_available_versions(self) -> List[str]:
        """Get list of all available Solidity compiler versions"""
        success, output = self._run_command(["solc-select", "versions"])
        if success:
            available_versions = []
            in_available_section = False
            for line in output.split("\n"):
                line = line.strip()
                if "Available" in line:
                    in_available_section = True
                    continue
                elif "Installed" in line:
                    in_available_section = False
                    continue

                if in_available_section and line:
                    available_versions.append(line)
            return available_versions
        return []

    def install_version(self, version: str) -> Tuple[bool, str]:
        """Install a specific Solidity compiler version"""
        success, output = self._run_command(["solc-select", "install", version])
        if success:
            self._refresh_versions()
            return True, f"Successfully installed Solidity {version}"
        else:
            return False, f"Failed to install Solidity {version}: {output}"

    def use_version(self, version: str) -> Tuple[bool, str]:
        """Select a specific Solidity compiler version"""
        success, output = self._run_command(["solc-select", "use", version])
        if success:
            # Update internal state immediately
            self.current_version = version
            # Give solc-select a moment to update
            import time

            time.sleep(0.2)
            return True, f"Successfully switched to Solidity {version}"
        else:
            return False, f"Failed to switch to Solidity {version}: {output}"

    def extract_pragma_version(self, contract_path: str) -> Optional[str]:
        """Extract the required Solidity version from a contract's pragma directive"""
        try:
            with open(contract_path, "r") as f:
                content = f.read()

            # Look for pragma solidity statement
            pragma_match = re.search(
                r"pragma\s+solidity\s+([^;]+);", content, re.IGNORECASE
            )
            if pragma_match:
                version_spec = pragma_match.group(1).strip()

                # Extract specific version number
                # Handle patterns like ^0.8.0, >=0.8.0, 0.8.0, etc.
                version_match = re.search(r"(\d+\.\d+\.\d+)", version_spec)
                if version_match:
                    return version_match.group(1)

                # Handle patterns like ^0.8 or >=0.8
                partial_match = re.search(r"(\d+\.\d+)", version_spec)
                if partial_match:
                    major_minor = partial_match.group(1)
                    # Default to .0 for patch version
                    return f"{major_minor}.0"

            return None
        except Exception as e:
            print(f"Error reading contract file: {e}")
            return None

    def auto_install_for_contract(self, contract_path: str) -> Tuple[bool, str]:
        """Automatically install and use the required Solidity version for a contract"""
        required_version = self.extract_pragma_version(contract_path)
        if not required_version:
            return False, "Could not determine required Solidity version from contract"

        # Check if version is already installed
        if required_version not in self.get_installed_versions():
            # Try to install it
            success, message = self.install_version(required_version)
            if not success:
                return False, message

        # Use the version
        success, message = self.use_version(required_version)
        return success, message

    def is_solc_select_available(self) -> bool:
        """Check if solc-select is available"""
        success, _ = self._run_command(["solc-select", "--help"])
        return success

    def get_status_info(self) -> dict:
        """Get comprehensive status information"""
        return {
            "current_version": self.get_current_version(),
            "installed_versions": self.get_installed_versions(),
            "solc_select_available": self.is_solc_select_available(),
        }
