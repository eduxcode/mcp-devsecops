# Container scanning helpers (Trivy, Docker security best practices)
import subprocess
import shutil
import json
import yaml
import re
from pathlib import Path
from typing import List, Dict, Optional

class ContainerSecurityChecker:
    """Classe para análise de segurança de containers"""
    
    SECURE_BASE_IMAGES = [
        "alpine:latest", "debian:slim", "ubuntu:latest",
        "python:slim", "node:slim", "nginx:alpine"
    ]
    
    SENSITIVE_PATTERNS = [
        r'(?i)password\s*=\s*[\'"][^\'"]+[\'"]',
        r'(?i)secret\s*=\s*[\'"][^\'"]+[\'"]',
        r'(?i)api[_-]key\s*=\s*[\'"][^\'"]+[\'"]',
        r'(?i)token\s*=\s*[\'"][^\'"]+[\'"]',
        r'(?i)credentials?\s*=\s*[\'"][^\'"]+[\'"]'
    ]

    def __init__(self):
        self.trivy_available = shutil.which('trivy') is not None

    def trivy_scan_image(self, image: str) -> str:
        """
        Executa análise de vulnerabilidades em imagem usando Trivy
        
        Args:
            image: Nome da imagem Docker a ser analisada
            
        Returns:
            str: Resultado da análise em formato JSON com vulnerabilidades encontradas
        """
        try:
            if not self.trivy_available:
                return '[Trivy não encontrado. Instale Trivy localmente ou use docker image aquasec/trivy]'
            
            cmd = [
                "trivy", "image",
                "--quiet",
                "--format", "json",
                "--severity", "HIGH,CRITICAL",  # Foco em vulnerabilidades críticas
                "--ignore-unfixed",  # Ignora vulnerabilidades sem correção
                image
            ]
            
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return res.stdout or res.stderr
            
        except Exception as e:
            return f"[Erro Trivy: {e}]"

    def analyze_dockerfile(self, path: str) -> Dict[str, List[str]]:
        """
        Análise avançada de Dockerfile com recomendações de segurança
        
        Args:
            path: Caminho para o Dockerfile
            
        Returns:
            Dict com issues críticas, warnings e sugestões
        """
        result = {"critical": [], "warnings": [], "suggestions": []}
        
        try:
            p = Path(path)
            content = p.read_text()
            lines = content.splitlines()
            
            # Análise de usuário root
            if 'USER root' in content:
                result["critical"].append("❌ Evite usar USER root em produção - crie um usuário específico")
            
            # Análise de imagem base
            base_image = None
            for line in lines:
                if line.startswith('FROM'):
                    base_image = line.split()[1]
                    if not any(secure in base_image for secure in self.SECURE_BASE_IMAGES):
                        result["warnings"].append(f"⚠️ Considere usar uma imagem base segura e atualizada. Sugestões: {', '.join(self.SECURE_BASE_IMAGES)}")
            
            # Verificação de COPY vs ADD
            if 'ADD' in content:
                result["warnings"].append("⚠️ Prefira COPY ao invés de ADD para maior segurança")
            
            # Multi-stage builds
            if content.count('FROM') == 1:
                result["suggestions"].append("💡 Considere usar multi-stage builds para reduzir a superfície de ataque")
            
            # Verificação de HEALTHCHECK
            if 'HEALTHCHECK' not in content:
                result["suggestions"].append("💡 Adicione HEALTHCHECK para monitoramento de saúde do container")
            
            # Análise de secrets expostos
            for pattern in self.SENSITIVE_PATTERNS:
                if re.search(pattern, content):
                    result["critical"].append("❌ Detectadas possíveis credenciais expostas no Dockerfile")
                    break
            
            # Verificação de versões fixas
            if ':latest' in content:
                result["warnings"].append("⚠️ Evite usar tags :latest - fixe versões específicas")
            
            return result
            
        except Exception as e:
            return {"error": [f"[Erro ao analisar Dockerfile: {e}]"]}

    def analyze_compose(self, path: str) -> Dict[str, List[str]]:
        """
        Analisa arquivo docker-compose.yml em busca de problemas de segurança
        
        Args:
            path: Caminho para o arquivo docker-compose.yml
            
        Returns:
            Dict com issues encontradas
        """
        result = {"critical": [], "warnings": [], "suggestions": []}
        
        try:
            with open(path) as f:
                compose = yaml.safe_load(f)
            
            services = compose.get('services', {})
            for service_name, service in services.items():
                # Verificação de privilégios
                if service.get('privileged', False):
                    result["critical"].append(f"❌ Serviço {service_name} está em modo privilegiado")
                
                # Verificação de portas expostas
                if 'ports' in service:
                    result["warnings"].append(f"⚠️ Serviço {service_name} expõe portas - verifique se necessário")
                
                # Verificação de volumes
                if 'volumes' in service:
                    for volume in service['volumes']:
                        if ':rw' in volume:
                            result["warnings"].append(f"⚠️ Volume com permissão de escrita em {service_name}")
                
                # Verificação de rede host
                if service.get('network_mode') == 'host':
                    result["critical"].append(f"❌ Serviço {service_name} usa network_mode: host")
                
                # Verificação de limites de recursos
                if not service.get('deploy', {}).get('resources', {}):
                    result["suggestions"].append(f"💡 Defina limites de recursos para {service_name}")
            
            return result
            
        except Exception as e:
            return {"error": [f"[Erro ao analisar docker-compose: {e}]"]}

    def format_results(self, results: Dict[str, List[str]]) -> str:
        """Formata os resultados da análise"""
        output = []
        
        if "critical" in results and results["critical"]:
            output.append("\n🚨 Problemas Críticos:")
            output.extend(results["critical"])
        
        if "warnings" in results and results["warnings"]:
            output.append("\n ⚠️ Avisos:")
            output.extend(results["warnings"])
        
        if "suggestions" in results and results["suggestions"]:
            output.append("\n💡 Sugestões:")
            output.extend(results["suggestions"])
        
        if "error" in results:
            output.append(f"\n❌ Erro: {results['error']}")
        
        return "\n".join(output) if output else "✅ Nenhum problema encontrado"
