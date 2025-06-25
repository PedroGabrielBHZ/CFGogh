#!/usr/bin/env python3

import sys

sys.path.append("src")

from solc_manager import SolcManager


def main():
    print("Testing SolcManager...")
    solc = SolcManager()

    print("Current version:", solc.get_current_version())
    print("Installed versions:", solc.get_installed_versions())

    # Test switching to a different known installed version
    print("\nTesting version switch to 0.8.0...")
    success, message = solc.use_version("0.8.0")
    print("Switch result:", success)
    print("Message:", message)

    print("Current version after switch:", solc.get_current_version())


if __name__ == "__main__":
    main()
