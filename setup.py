#!/usr/bin/env python3
"""
Sourcerer Dependency Setup Script
Sets up required dependencies like ACX.jar
"""

import sys
import os
import platform
import subprocess
import urllib.request
import shutil
from pathlib import Path

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

    @staticmethod
    def supports_color():
        """Check if terminal supports color"""
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

    @classmethod
    def disable_if_needed(cls):
        """Disable colors on Windows or non-TTY"""
        if not cls.supports_color() or platform.system() == 'Windows':
            cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = cls.NC = ''

Colors.disable_if_needed()

# Installation paths
if platform.system() == 'Windows':
    INSTALL_SHARE = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'sourcerer'
    ACX_DIR = INSTALL_SHARE / 'java'
else:
    INSTALL_SHARE = Path('/usr/local/share')
    ACX_DIR = INSTALL_SHARE / 'java'

ACX_JAR = ACX_DIR / 'acx.jar'
ACX_URL = 'https://github.com/AppleCommander/acx/releases/latest/download/acx.jar'

def echo_info(msg):
    print(f"{Colors.BLUE}==>{Colors.NC} {msg}")

def echo_success(msg):
    print(f"{Colors.GREEN}✓{Colors.NC} {msg}")

def echo_error(msg):
    print(f"{Colors.RED}✗{Colors.NC} {msg}", file=sys.stderr)

def echo_warning(msg):
    print(f"{Colors.YELLOW}⚠{Colors.NC} {msg}")

def check_command(cmd):
    """Check if a command exists"""
    return shutil.which(cmd) is not None

def check_requirements():
    """Check for required tools"""
    echo_info("Checking requirements...")

    missing = []

    if not check_command('java'):
        missing.append('java')

    if len(missing) > 0:
        echo_error(f"Missing required tools: {', '.join(missing)}")
        print("\nInstallation instructions:")

        system = platform.system()
        if system == 'Darwin':  # macOS
            print("  brew install openjdk")
        elif system == 'Linux':
            if Path('/etc/debian_version').exists():
                print("  sudo apt-get install default-jre")
            elif Path('/etc/redhat-release').exists():
                print("  sudo yum install java-latest-openjdk")
            else:
                print("  Install Java JRE using your distribution's package manager")
        elif system == 'Windows':
            print("  Download and install Java from: https://www.oracle.com/java/technologies/downloads/")

        sys.exit(1)

    echo_success("All requirements met")

def needs_elevation():
    """Check if we need elevated privileges"""
    if platform.system() == 'Windows':
        import ctypes
        return not ctypes.windll.shell32.IsUserAnAdmin()
    else:
        return os.geteuid() != 0 if hasattr(os, 'geteuid') else False

def run_elevated(args):
    """Re-run script with elevated privileges"""
    system = platform.system()

    if system == 'Windows':
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(args), None, 1
        )
    else:
        os.execvp('sudo', ['sudo', sys.executable] + args)

def install_acx():
    """Download and install ACX.jar"""
    echo_info("Checking ACX.jar installation...")

    # Check if already installed and functional
    if ACX_JAR.exists():
        echo_success(f"ACX.jar already installed at {ACX_JAR}")

        # Test if it works
        try:
            result = subprocess.run(
                ['java', '-jar', str(ACX_JAR), '--version'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                echo_success("ACX.jar is functional")
                return
            else:
                echo_warning("ACX.jar exists but may not be functional, reinstalling...")
                ACX_JAR.unlink()
        except Exception as e:
            echo_warning(f"ACX.jar test failed: {e}, reinstalling...")
            ACX_JAR.unlink()

    echo_info(f"Installing ACX.jar to {ACX_JAR}...")

    # Create directory if it doesn't exist
    if not ACX_DIR.exists():
        echo_info(f"Creating directory {ACX_DIR}...")
        try:
            ACX_DIR.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            echo_error(f"Permission denied creating {ACX_DIR}")
            if needs_elevation():
                echo_info("Re-running with elevated privileges...")
                run_elevated(sys.argv)
                sys.exit(0)
            else:
                sys.exit(1)

    # Download ACX.jar
    temp_jar = Path('/tmp/acx.jar') if platform.system() != 'Windows' else Path(os.environ['TEMP']) / 'acx.jar'

    try:
        echo_info(f"Downloading ACX.jar from {ACX_URL}...")
        with urllib.request.urlopen(ACX_URL) as response, open(temp_jar, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
    except Exception as e:
        echo_error(f"Failed to download ACX.jar: {e}")
        sys.exit(1)

    # Install
    try:
        echo_info("Installing ACX.jar...")
        shutil.move(str(temp_jar), str(ACX_JAR))
        ACX_JAR.chmod(0o644)
    except PermissionError:
        echo_error(f"Permission denied installing to {ACX_JAR}")
        if needs_elevation():
            echo_info("Re-running with elevated privileges...")
            run_elevated(sys.argv)
            sys.exit(0)
        else:
            sys.exit(1)

    # Verify installation
    try:
        result = subprocess.run(
            ['java', '-jar', str(ACX_JAR), '--version'],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            echo_success("ACX.jar installed successfully")
        else:
            echo_error("ACX.jar installation failed or is not functional")
            sys.exit(1)
    except Exception as e:
        echo_error(f"ACX.jar verification failed: {e}")
        sys.exit(1)

def show_usage():
    """Show usage information"""
    print("Usage: python3 setup.py [OPTIONS]")
    print("")
    print("Options:")
    print("  --help          Show this help message")
    print("")
    print("This script installs required dependencies:")
    print(f"  - ACX.jar to {ACX_DIR}")
    print("")
    print("After running this script, build and install sourcerer with:")
    print("  mkdir build && cd build")
    print("  cmake ..")
    print("  make")

    if platform.system() == 'Windows':
        print("  cmake --install . --prefix \"C:/Program Files/sourcerer\"")
    else:
        print("  sudo make install")
    print("")
    print("Note: Administrator/sudo access may be required for system-wide installation")

def main():
    """Main installation flow"""
    # Parse arguments
    if '--help' in sys.argv:
        show_usage()
        sys.exit(0)

    print("")
    print("=" * 42)
    print("  Sourcerer Dependency Setup v1.0.0")
    print("=" * 42)
    print("")

    # Check Python version
    if sys.version_info < (3, 6):
        echo_error("Python 3.6 or higher is required")
        sys.exit(1)

    check_requirements()
    install_acx()

    print("")
    echo_success("Dependency setup complete!")
    print("")
    print("Next steps:")
    print("  1. Build sourcerer:")
    print("       mkdir build && cd build")
    print("       cmake ..")

    if platform.system() == 'Windows':
        print("       cmake --build . --config Release")
    else:
        print("       make -j8")

    print("")
    print("  2. Run tests (optional):")
    print("       cmake .. -DBUILD_TESTING=ON")

    if platform.system() == 'Windows':
        print("       cmake --build . --config Release")
        print("       ctest -C Release --output-on-failure")
    else:
        print("       make -j8")
        print("       ctest --output-on-failure")

    print("")
    print("  3. Install sourcerer:")

    if platform.system() == 'Windows':
        print("       cmake --install . --prefix \"C:/Program Files/sourcerer\"")
    else:
        print("       sudo make install")

    print("")
    print(f"ACX.jar installed at: {ACX_JAR}")
    print("")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        echo_warning("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        echo_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
