#!/bin/bash
set -e

echo "🚀 Starting full setup for Docker ML Scanner..."
sudo apt-get update -y

echo "📦 Installing basic dependencies..."
sudo apt-get install -y curl wget gnupg lsb-release ca-certificates python3 python3-pip

# ---------------------------------------------------------------------------
# 1️⃣ INSTALL DOCKER
# ---------------------------------------------------------------------------

echo "✅ Docker installed successfully!"
docker --version

# ---------------------------------------------------------------------------
# 2️⃣ INSTALL SYFT (SBOM generator)
# ---------------------------------------------------------------------------
echo "🧾 Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
syft --version

# ---------------------------------------------------------------------------
# 3️⃣ INSTALL GRYPE (Vulnerability scanner)
# ---------------------------------------------------------------------------
echo "🧨 Installing Grype..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
grype --version

# ---------------------------------------------------------------------------
# 4️⃣ INSTALL TRIVY (Comprehensive scanner)
# ---------------------------------------------------------------------------
echo "🛡️ Installing Trivy..."
wget -q https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-64bit.tar.gz
tar zxvf trivy_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
rm trivy_Linux-64bit.tar.gz
trivy --version

# ---------------------------------------------------------------------------
# 5️⃣ INSTALL PYTHON DEPENDENCIES
# ---------------------------------------------------------------------------
echo "🐍 Installing Python libraries..."
pip install --upgrade pip
pip install pandas tqdm requests docker rich loguru numpy

echo "✅ Python dependencies installed successfully!"

# ---------------------------------------------------------------------------
# 6️⃣ TEST ALL TOOLS
# ---------------------------------------------------------------------------
echo "🔍 Verifying installations..."
docker --version
syft --version
grype --version
trivy --version
python3 --version

echo ""
echo "🎉 Setup complete!"
echo "You can now run your scanner with:"
echo "   python extract_features.py extract"
echo ""

