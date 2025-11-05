# 🧠 **MCP DevSecOps Assistant — Guia Completo**

## 📑 **Índice**
1. [Instalação](#️-1-instalação)
   - [Ubuntu / Debian / WSL](#-ubuntu--debian--wsl)
   - [macOS](#-macos-intel-ou-m1m2)
   - [Windows](#-windows-1011)
2. [Preparação do ambiente](#-2-preparação-do-ambiente)
3. [Uso prático](#-3-uso-prático)
   - [Comandos principais](#-comandos-principais)
4. [Exemplos por módulo](#-4-exemplos-por-módulo)
   - [SAST](#-sast--análise-estática)
   - [SCA](#-sca--dependências)
   - [DAST](#-dast--teste-dinâmico-owasp-zap)
   - [Containers](#-containers--segurança-de-imagens-trivy)
   - [Políticas](#-políticas--kubernetes--opa--kyverno)
   - [Monitoramento](#-monitoramento--prometheus--elk--grafana)
5. [Geração de Relatórios](#-5-geração-de-relatórios)
6. [Integração com Continue.dev](#-6-integração-com-continuedev)
7. [Dicas rápidas](#-7-dicas-rápidas)
8. [Expansões futuras](#-8-expansões-futuras)
9. [Guia de Contribuição](#-9-guia-de-contribuição)
   - [Diretrizes Gerais](#-diretrizes-gerais)
   - [Áreas Prioritárias](#-áreas-prioritárias-para-contribuição)
   - [Processo de Contribuição](#-processo-de-contribuição)
10. [Créditos e Conformidade](#-10-créditos-e-conformidade)

---

## 🧩 **Sobre o projeto**
O **MCP DevSecOps Assistant** é um agente local (Model Context Protocol) projetado para **auxiliar no desenvolvimento e gestão de pipelines DevSecOps End-to-End** de forma **segura, autônoma e independente da aplicação principal**.

⚙️ Ele foi desenvolvido para:
- Acompanhar o residente em todas as fases do projeto DevSecOps;
- Executar análises automatizadas (SAST, SCA, DAST, Containers, Políticas, APIs);
- Gerar relatórios técnicos e executivos com base em normas oficiais (NIST, OWASP, CNCF);
- Oferecer recomendações baseadas em práticas de segurança open-source;
- Funcionar **localmente**, garantindo **segurança, privacidade e compliance institucional**.

---

## 🛡️ **Nota importante sobre uso local e compliance**
Este MCP roda **somente no ambiente local do desenvolvedor** (Linux, macOS ou Windows).  
Ele **não interfere diretamente no código-fonte, repositórios ou pipelines da instituição**, garantindo:

- **Isolamento total do ambiente institucional**  
- **Conformidade com políticas de segurança e sigilo de dados**  
- **Autonomia e liberdade técnica** para o residente trabalhar com segurança  
- **Zero impacto no código-fonte da aplicação real**

> 🧩 O MCP atua como uma **ferramenta de apoio técnico**, e não como parte da aplicação que você está desenvolvendo.  
> Ele serve para **analisar, sugerir, documentar e simular**, mas **não altera nem executa nada diretamente nos repositórios oficiais.**

---

## 🧱 **Arquitetura geral**

```
┌──────────────────────────────┐
│ VSCode + Continue.dev        │  ← Interface interativa
└──────────────┬───────────────┘
               │
      ┌────────▼────────┐
      │ MCP DevSecOps   │  ← (Python + LangChain + RAG)
      │ tools/devsecops_mcp.py │
      └────────┬────────┘
               │
 ┌─────────────▼───────────────────────────┐
 │  Módulos técnicos (Bandit, ZAP, Trivy)  │
 │  + Base RAG (OWASP, NIST, CNCF)         │
 └─────────────────────────────────────────┘
               │
        ┌──────▼──────┐
        │  Ollama     │ ← IA local (Llama3)
        │  Gemini API │ ← (opcional)
        └─────────────┘
```

---

# ⚙️ **1. Instalação**

## 🐧 **Ubuntu / Debian / WSL**
```bash
git clone https://github.com/eduxcode/mcp-devsecops.git
cd mcp-devsecops
chmod +x install.sh
./install.sh
```
> 💡 Após instalar, reinicie o terminal e execute:
```bash
ollama pull llama3
```

---

## 🍎 **macOS (Intel ou M1/M2)**
```bash
git clone https://github.com/eduxcode/mcp-devsecops.git
cd mcp-devsecops
chmod +x install.sh
./install.sh
```
Instale manualmente:
- [Docker Desktop](https://www.docker.com/get-started)
- [Ollama](https://ollama.com/download)

---

## 🪟 **Windows 10/11**
1. Instale:
   - [Docker Desktop](https://www.docker.com/get-started)
   - [Python 3.10+](https://www.python.org/downloads/)
   - [Git](https://git-scm.com/downloads)
   - [Ollama (opcional)](https://ollama.com/download)
2. Clone o projeto:
   ```powershell
   git clone https://github.com/eduxcode/mcp-devsecops.git
   cd mcp-devsecops
   ```
3. Execute:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\install.ps1
   ```

---

# 📚 **2. Preparação do ambiente**

1️⃣ Coloque o PDF do seu **plano de trabalho** em:
```
data/plano_de_trabalho/Plano_DevSecOps.pdf
```

2️⃣ Crie a base de conhecimento (RAG):
```bash
python tools/rag_loader.py
```
> Isso baixa e indexa documentos oficiais (OWASP, NIST, CNCF).

3️⃣ Configure o VSCode com o plugin [Continue.dev](https://marketplace.visualstudio.com/items?itemName=Continue.continue).  
O arquivo `.continue/config.json` já está preparado.

---

# 🚀 **3. Uso prático**

## ✅ **Comandos principais**

| Ação | Comando | Descrição |
|------|----------|-----------|
| Ler plano | `python tools/devsecops_mcp.py ler-plano` | Lê o PDF do plano |
| Gerar relatório | `python tools/devsecops_mcp.py gerar-relatorio` | Gera relatório técnico |
| Analisar arquivo | `python tools/devsecops_mcp.py analisar <arquivo>` | Avalia YAML, Dockerfile, Rego |
| Rodar scan | `python tools/devsecops_mcp.py scan <sast|dast|container> <target>` | Executa varredura específica |

---

# 🔍 **4. Exemplos por módulo**

### 🔹 SAST — Análise Estática
```bash
python tools/devsecops_mcp.py scan sast ./src
```
> Varredura com Bandit.  

---

### 🔹 SCA — Dependências
```bash
docker run --rm -v $(pwd):/src owasp/dependency-check --project MyApp --scan /src
```

---

### 🔹 DAST — Teste Dinâmico (OWASP ZAP)
```bash
python tools/devsecops_mcp.py scan dast http://localhost:8080
```

---

### 🔹 Containers — Segurança de Imagens (Trivy)
```bash
python tools/devsecops_mcp.py scan container myapp:latest
```

---

### 🔹 Políticas — Kubernetes / OPA / Kyverno
```bash
python tools/devsecops_mcp.py analisar kubernetes/policies/limit-cpu.yaml
```

---

### 🔹 Monitoramento — Prometheus / ELK / Grafana
Valida e analisa configurações de monitoramento:
```bash
python tools/monitoring_check.py --config prometheus.yml
python tools/monitoring_check.py --analyze-logs elk/logstash.conf
python tools/monitoring_check.py --check-dashboard grafana/dashboard.json
```

> 💡 Suporta validação de:
> - Configurações Prometheus (alertas, regras, targets)
> - Pipelines Logstash e configurações do Elasticsearch
> - Dashboards Grafana (métricas, visualizações)

---

# 🧾 **5. Geração de Relatórios**
```bash
python tools/devsecops_mcp.py gerar-relatorio
```
> Gera `relatorios/relatorio_unificado.md` com:
> - Resumo do plano  
> - Resultados SAST/Container  
> - Recomendações automáticas  

---

# 🧩 **6. Integração com Continue.dev**
Com o Continue instalado no VSCode:
```
> MCP: Analisar pipeline GitLab
> MCP: Gerar relatório DevSecOps
> MCP: Explicar o NIST SSDF nesta aplicação
```
O Continue chama o MCP local, que consulta sua base RAG (OWASP, NIST, CNCF) e responde contextualizado.

---

# ⚡ **7. Dicas rápidas**

| Problema | Solução |
|-----------|----------|
| Trivy/ZAP não encontrados | `docker pull aquasec/trivy` e `docker pull owasp/zap2docker-stable` |
| Relatório vazio | Verifique o PDF do plano e logs em `data/logs/` |
| Ollama inativo | `ollama serve` ou `ollama run llama3` |
| Erros de permissão | `sudo usermod -aG docker $USER && newgrp docker` |
| Execução lenta | Ajuste `timeout` nos scripts em `tools/` |
| Base RAG desatualizada | Execute `python tools/rag_loader.py --update` |
| Problemas com Docker | Verifique `docker ps` e `docker info` |
| Erros de memória | Ajuste `MAX_MEMORY` em `tools/devsecops_mcp.py` |

---

# 🔮 **8. Expansões futuras**
- SOAR open-source (TheHive / Shuffle / Cortex)
- Integração com Vulnerability Management (DefectDojo)
- Relatórios em PDF com gráficos e métricas
- Dashboards dinâmicos com Grafana
- Políticas customizadas Kyverno/OPA
- Métricas OWASP SAMM (maturidade DevSecOps)
- Integração com GitLab/GitHub Security Center
- Análise de compliance com CIS Benchmarks

---

# � **9. Guia de Contribuição**

## 📋 **Diretrizes Gerais**
- Todo código deve seguir os princípios de DevSecOps
- Mantenha o foco em segurança e compliance
- Priorize ferramentas open-source
- Documente todas as alterações
- Mantenha a compatibilidade com execução local

## 🎯 **Áreas Prioritárias para Contribuição**

### 1️⃣ **SOAR Integration (TheHive/Shuffle/Cortex)**
- Implementar conectores para plataformas SOAR
- Desenvolver playbooks de automação
- Integrar com sistemas de alerta

### 2️⃣ **Vulnerability Management**
- Integração com DefectDojo
- Sistema de priorização de vulnerabilidades
- Dashboards de métricas de segurança

### 3️⃣ **Relatórios e Analytics**
- Geração de relatórios PDF customizáveis
- Gráficos e visualizações com Grafana
- Métricas de maturidade OWASP SAMM

### 4️⃣ **Políticas e Compliance**
- Templates Kyverno/OPA
- Validadores CIS Benchmark
- Checagem automática de compliance

### 5️⃣ **Integrações com DevSecOps**
- GitLab/GitHub Security Center
- Pipeline templates
- Validadores de IaC

## 🔄 **Processo de Contribuição**

1. **Preparação**
   ```bash
   git clone https://github.com/eduxcode/mcp-devsecops.git
   git checkout -b feature/sua-feature
   ```

2. **Desenvolvimento**
   - Siga o estilo de código existente
   - Adicione testes unitários
   - Atualize a documentação
   - Mantenha a compatibilidade com todos os OS

3. **Testes**
   ```bash
   python -m pytest tests/
   python tools/devsecops_mcp.py test
   ```

4. **Documentação**
   - Atualize o README.md
   - Documente novas funcionalidades
   - Adicione exemplos de uso

5. **Pull Request**
   - Descreva claramente as mudanças
   - Referencie issues relacionadas
   - Aguarde review do time

## 📝 **Guidelines de Código**

- Use Python 3.10+ com type hints
- Siga PEP 8 e pratique clean code
- Documente funções e classes
- Evite dependências desnecessárias
- Mantenha a execução local

## 🔒 **Requisitos de Segurança**

- Não exponha dados sensíveis
- Valide inputs e sanitize outputs
- Use HTTPS para APIs externas
- Siga princípios OWASP
- Mantenha dependências atualizadas

## 🚫 **O que Evitar**

- Código que requer serviços cloud
- Dependências proprietárias
- Modificações diretas em pipelines
- Código não testado
- Falta de documentação

---

# �🧾 **10. Créditos e Conformidade**
📘 Desenvolvido por **Davi Soares**  
Residênte em **DevSecOps — RNP (Pipeline End-to-End com Ferramentas Open-Source)**  

Normas aplicadas:
- **NIST SP 800-218** — Secure Software Development Framework  
- **OWASP Top 10** & **OWASP API Security Top 10**  
- **CNCF Security Whitepaper v2**  
- **OWASP SAMM**  

> ⚙️ **Este MCP é uma ferramenta auxiliar de análise e aprendizado DevSecOps.**  
> Ele opera **localmente por motivos de segurança e compliance**, **não interagindo nem modificando diretamente** as aplicações ou pipelines da instituição.
