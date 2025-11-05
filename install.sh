#!/usr/bin/env bash
set -e
echo "🚀 Instalando dependências do MCP DevSecOps (Linux / WSL / macOS)..."
# Basic package install (Debian/Ubuntu)
if [[ "$(uname -s)" == "Linux" ]]; then
  if command -v apt >/dev/null 2>&1; then
    sudo apt update -y
    sudo apt install -y python3 python3-pip git curl docker.io docker-compose
  fi
fi
# Python packages
python3 -m pip install --upgrade pip
python3 -m pip install langchain chromadb PyPDF2 requests openai bandit
# Ollama (if available)
if ! command -v ollama &> /dev/null; then
  echo "Instalador do Ollama não encontrado automaticamente. Visite https://ollama.com/install para instruções."
else
  echo "Ollama detectado. (Opcional) baixar modelo recomendado..."
  # ollama pull llama3  # uncomment if you want automatic pull
fi
# Docker images commonly used
docker pull sonarqube || true
docker pull owasp/zap2docker-stable || true
docker pull aquasec/trivy || true
docker pull prom/prometheus || true
docker pull grafana/grafana || true
echo "✅ Instalação (base) concluída. Leia README.md para passos adicionais."
