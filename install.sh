#!/bin/bash

# OWASP Security Scanner Installation Script
# This script installs all required dependencies for the OWASP Security Scanner

# Color codes for prettier output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "======================================================================"
echo "       ___ _    _  _   ___ ___    ___ ___ ___ _   _ ___ ___ ___ _   _ "
echo "      / _ \ \  / \/ \ / __| _ \  / __| __/ __| | | | _ \_ _| __| | | |"
echo "     | (_) | |/ _  _  _\__ \  _/ \__ \ _|\__ \ |_| |   /| || _|| |_| |"
echo "      \___/|_/_/ \/_/\_\___/_|   |___/___|___/\___/|_|_\___|___|_\___/"
echo "                                                                 INSTALLER"
echo "======================================================================"
echo -e "${NC}"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${YELLOW}Warning: Not running as root. Some installations might fail.${NC}"
  echo -e "Consider running with ${GREEN}sudo${NC} if you encounter permission issues."
  echo ""
  read -p "Continue anyway? (y/n) " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Installation aborted.${NC}"
    exit 1
  fi
fi

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to display step information
step() {
  echo -e "\n${GREEN}[+]${NC} $1..."
}

# Function to display substep information
substep() {
  echo -e "  ${BLUE}[-]${NC} $1"
}

# Function to handle errors
error() {
  echo -e "${RED}[!] Error: $1${NC}"
  if [ "$2" = "fatal" ]; then
    echo -e "${RED}[!] Fatal error. Exiting installation.${NC}"
    exit 1
  fi
}

# Check Python version
step "Checking Python version"
if command_exists python3; then
  PYTHON_VERSION=$(python3 --version | cut -d " " -f 2)
  PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
  PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
  
  if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 7 ]; then
    substep "Python $PYTHON_VERSION detected - OK"
    PYTHON_CMD="python3"
  else
    error "Python 3.7+ required, found $PYTHON_VERSION" "fatal"
  fi
else
  error "Python 3 not found. Please install Python 3.7 or higher" "fatal"
fi

# Check and install pip if needed
step "Checking pip installation"
if command_exists pip3; then
  substep "pip3 is already installed"
else
  substep "Installing pip..."
  if command_exists apt-get; then
    apt-get update && apt-get install -y python3-pip || error "Failed to install pip with apt-get"
  elif command_exists yum; then
    yum install -y python3-pip || error "Failed to install pip with yum"
  elif command_exists brew; then
    brew install python3 || error "Failed to install pip with Homebrew"
  else
    error "Could not determine package manager. Please install pip3 manually."
  fi
fi

# Install virtual environment
step "Setting up virtual environment"
if ! command_exists virtualenv; then
  substep "Installing virtualenv..."
  pip3 install virtualenv || error "Failed to install virtualenv"
fi

# Create and activate virtual environment
if [ ! -d "venv" ]; then
  substep "Creating virtual environment..."
  virtualenv venv || error "Failed to create virtual environment"
else
  substep "Virtual environment already exists"
fi

# Activate virtual environment (for current script)
substep "Activating virtual environment..."
source venv/bin/activate || error "Failed to activate virtual environment" "fatal"

# Install Python dependencies
step "Installing Python dependencies"
substep "Installing required packages..."
pip install requests beautifulsoup4 dnspython colorama urllib3 argparse concurrent-log-handler || error "Failed to install Python dependencies"

# Install Go (for assetfinder)
install_go() {
  step "Installing Go (required for assetfinder)"
  
  if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    substep "Go $GO_VERSION is already installed"
  else
    substep "Downloading and installing Go..."
    
    # Determine OS and architecture
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
      ARCH="amd64"
    elif [ "$ARCH" = "i386" ] || [ "$ARCH" = "i686" ]; then
      ARCH="386"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
      ARCH="arm64"
    fi
    
    GO_VERSION="1.21.1"  # Use a stable Go version
    GO_TAR="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    GO_URL="https://golang.org/dl/${GO_TAR}"
    
    # Download and install Go
    wget -q $GO_URL -O /tmp/$GO_TAR || error "Failed to download Go"
    tar -C /usr/local -xzf /tmp/$GO_TAR || error "Failed to extract Go"
    rm /tmp/$GO_TAR
    
    # Set PATH for Go
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> $HOME/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    substep "Go installation complete"
  fi
}

# Install assetfinder for subdomain discovery
install_assetfinder() {
  step "Installing assetfinder (for subdomain discovery)"
  
  if command_exists assetfinder; then
    substep "assetfinder is already installed"
  else
    if ! command_exists go; then
      install_go
    fi
    
    substep "Installing assetfinder with go..."
    go install github.com/tomnomnom/assetfinder@latest || error "Failed to install assetfinder"
    
    if [ ! -f "$HOME/go/bin/assetfinder" ]; then
      error "assetfinder installation failed"
    else
      substep "assetfinder installed successfully"
    fi
  fi
}

# Ask user if they want to install Go and assetfinder
echo ""
read -p "Do you want to install Go and assetfinder for subdomain discovery? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  install_assetfinder
else
  substep "Skipping assetfinder installation"
  echo -e "${YELLOW}Note: Subdomain discovery functionality will be limited without assetfinder${NC}"
fi

# Create the requirements.txt file
step "Creating requirements.txt file"
cat > requirements.txt << EOF
requests>=2.28.1
beautifulsoup4>=4.11.1
dnspython>=2.2.1
colorama>=0.4.5
urllib3>=1.26.12
argparse>=1.4.0
concurrent-log-handler>=0.9.20
EOF
substep "Created requirements.txt with all dependencies"

# Make the scanner executable
step "Making the scanner executable"
if [ -f "scanner.py" ]; then
  chmod +x scanner.py
  substep "Scanner is now executable with './scanner.py'"
else
  error "scanner.py not found - please make sure the scanner file is in the current directory"
fi

# Setup complete
echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}✓ OWASP Scanner installation complete!${NC}"
echo -e "${GREEN}=========================================${NC}\n"

echo -e "To use the scanner, run:"
echo -e "  ${BLUE}source venv/bin/activate${NC}"
echo -e "  ${BLUE}./scanner.py https://example.com${NC}\n"

echo -e "To see all options:"
echo -e "  ${BLUE}./scanner.py --help${NC}\n"

echo -e "${YELLOW}Note: Always obtain proper authorization before scanning any systems.${NC}"