#!/bin/bash

# Function to check if a command exists
command_exists () {
  command -v "$1" >/dev/null 2>&1
}

missing_deps=0

# Check for Node.js
if ! (command_exists node || command_exists nodejs); then
  missing_deps=1
  echo "❌ Node.js is not installed."
  echo ""
  echo "To install Node.js, visit the official download page:"
  echo "👉 https://nodejs.org/en/download/"
  echo ""
  echo "Or install it using a package manager:"
  echo ""
  echo "🔹 macOS (Homebrew):"
  echo "    brew install node"
  echo ""
  echo "🔹 Ubuntu/Debian:"
  echo "    curl -fsSL https://deb.nodesource.com/setup_current.x | sudo -E bash -"
  echo "    sudo apt-get install -y nodejs"
  echo ""
  echo "🔹 CentOS/RHEL:"
  echo "    curl -fsSL https://rpm.nodesource.com/setup_current.x | sudo bash -"
  echo "    sudo yum install -y nodejs"
  echo ""
  echo "🔹 Arch Linux:"
  echo "    sudo pacman -S nodejs"
  echo ""
fi

# Check for npm
if ! command_exists npm; then
  missing_deps=1
  echo "❌ npm is not installed."
  echo ""
  echo "npm typically comes with Node.js. Please install Node.js to get npm."
  echo ""
  echo "Alternatively, install npm using a package manager:"
  echo ""
  echo "🔹 macOS (Homebrew):"
  echo "    brew install npm"
  echo ""
  echo "🔹 Ubuntu/Debian:"
  echo "    sudo apt-get install npm"
  echo ""
  echo "🔹 CentOS/RHEL:"
  echo "    sudo yum install npm"
  echo ""
  echo "🔹 Arch Linux:"
  echo "    sudo pacman -S npm"
  echo ""
fi

# Exit with a bad exit code if any dependencies are missing
if [ "$missing_deps" -ne 0 ]; then
  echo "Install the missing dependencies and ensure they are on your path. Then run this command again."
  # TODO: remove sleep when cli bug is fixed
  sleep 2
  exit 1
fi

# Check for extism-js
if ! command_exists extism-js; then
  echo "❌ extism-js is not installed."
  echo ""
  echo "extism-js is needed to compile the plug-in. You can find the instructions to install it here: https://github.com/extism/js-pdk"
  echo ""
  echo "Alternatively, you can use an install script."
  echo ""
  echo "🔹 Mac / Linux:"
  echo "curl -L https://raw.githubusercontent.com/extism/js-pdk/main/install.sh | bash"
  echo ""
  echo "🔹 Windows:"
  echo "powershell Invoke-WebRequest -Uri https://raw.githubusercontent.com/extism/js-pdk/main/install-windows.ps1 -OutFile install-windows.ps1"
  echo "powershell -executionpolicy bypass -File .\install-windows.ps1"
  echo ""
  # TODO: remove sleep when cli bug is fixed
  sleep 2
  exit 1
fi

npm install
