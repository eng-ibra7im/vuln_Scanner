#!/usr/bin/env python3
"""
Setup and Installation Script for Subdomain Enumeration Orchestrator
Checks dependencies and helps with initial configuration.
"""

import subprocess
import sys
import shutil
from pathlib import Path


def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def check_python_version():
    """Check if Python version is adequate"""
    print_header("Checking Python Version")

    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False

    print(
        f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    return True


def install_python_dependencies():
    """Install Python dependencies"""
    print_header("Installing Python Dependencies")

    try:
        print("Installing base requirements...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        )
        print("✓ Base requirements installed")

        # Ask about API dependencies
        response = input("\nInstall API server dependencies? (y/n): ").lower()
        if response == "y":
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-r", "requirements_api.txt"]
            )
            print("✓ API requirements installed")

        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False


def check_external_tools():
    """Check if external subdomain enumeration tools are installed"""
    print_header("Checking External Tools")

    tools = {
        "subfinder": "subfinder",
        "amass": "amass",
        "assetfinder": "assetfinder",
        "ffuf": "ffuf",
    }

    installed = []
    missing = []

    for tool_name, command in tools.items():
        if shutil.which(command):
            print(f"✓ {tool_name} is installed")
            installed.append(tool_name)
        else:
            print(f"✗ {tool_name} is NOT installed")
            missing.append(tool_name)

    if missing:
        print("\n⚠ Missing tools detected!")
        print("\nTo install missing tools:")

        if "subfinder" in missing:
            print("\n  Subfinder:")
            print(
                "    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            )

        if "amass" in missing:
            print("\n  Amass:")
            print("    go install -v github.com/owasp-amass/amass/v4/...@master")

        if "assetfinder" in missing:
            print("\n  Assetfinder:")
            print("    go install -v github.com/tomnomnom/assetfinder@latest")

        if "ffuf" in missing:
            print("\n  ffuf:")
            print("    go install github.com/ffuf/ffuf/v2@latest")

        print("\nNote: Make sure your Go bin directory is in PATH")
        print("      (usually ~/go/bin or %USERPROFILE%\\go\\bin)")

    return len(installed) > 0


def create_configuration():
    """Create default configuration if it doesn't exist"""
    print_header("Configuration Setup")

    config_path = Path("config.json")

    if config_path.exists():
        print("✓ Configuration file already exists")
        response = input("  Overwrite with default configuration? (y/n): ").lower()
        if response != "y":
            print("  Keeping existing configuration")
            return True

    try:
        from config import create_default_config

        create_default_config()
        print("✓ Default configuration created")
        return True
    except Exception as e:
        print(f"❌ Error creating configuration: {e}")
        return False


def create_directories():
    """Create necessary directories"""
    print_header("Creating Directories")

    directories = ["results", "wordlists"]

    for dir_name in directories:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"✓ Created {dir_name}/ directory")
        else:
            print(f"✓ {dir_name}/ directory exists")

    # Create .gitkeep in wordlists
    gitkeep = Path("wordlists/.gitkeep")
    if not gitkeep.exists():
        gitkeep.touch()

    return True


def run_test():
    """Run a basic test to verify installation"""
    print_header("Running Test")

    try:
        from config import Config
        from orchestrator import SubdomainOrchestrator

        print("✓ All modules imported successfully")

        # Try to create orchestrator
        config = Config.load("config.json")
        orchestrator = SubdomainOrchestrator(config)

        print("✓ Orchestrator initialized successfully")

        return True
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False


def print_next_steps():
    """Print next steps for the user"""
    print_header("Setup Complete!")

    print("\n📋 Next Steps:\n")
    print(
        "1. Edit config.json to enable/disable tools based on what you have installed"
    )
    print("2. Run a test scan:")
    print("     python orchestrator.py example.com")
    print("\n3. Or use the CLI interface:")
    print("     python cli.py example.com --summary-only")
    print("\n4. For API server:")
    print("     python api.py --host 0.0.0.0 --port 5000")
    print("\n📖 Documentation:")
    print("   - README.md - Main documentation")
    print("   - API_EXAMPLES.md - API usage examples")
    print("\n⚠ Important Reminders:")
    print("   - Only scan domains you own or have permission to test")
    print("   - This tool is for educational/research purposes only")
    print("   - Ensure compliance with all applicable laws")
    print("\n" + "=" * 60)


def main():
    """Main setup function"""
    print("\n" + "=" * 60)
    print("  Subdomain Enumeration Orchestrator - Setup")
    print("  Version 1.0.0")
    print("=" * 60)

    # Check Python version
    if not check_python_version():
        sys.exit(1)

    # Install Python dependencies
    if not install_python_dependencies():
        print("\n⚠ Warning: Some Python dependencies failed to install")
        response = input("Continue anyway? (y/n): ").lower()
        if response != "y":
            sys.exit(1)

    # Check external tools
    if not check_external_tools():
        print("\n⚠ Warning: No external tools found")
        response = input("Continue anyway? (y/n): ").lower()
        if response != "y":
            sys.exit(1)

    # Create configuration
    if not create_configuration():
        sys.exit(1)

    # Create directories
    if not create_directories():
        sys.exit(1)

    # Run test
    if not run_test():
        print("\n⚠ Warning: Test failed")
        response = input("Continue anyway? (y/n): ").lower()
        if response != "y":
            sys.exit(1)

    # Print next steps
    print_next_steps()


if __name__ == "__main__":
    main()
