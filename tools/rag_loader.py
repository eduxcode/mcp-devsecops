#!/usr/bin/env python3
import os
import sys
import requests
import logging
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rag_loader.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Diretórios
DATA_DIR = Path.home() / "projetos/devsecops/data/knowledge_base"
DB_DIR = Path.home() / "projetos/devsecops/chromadb"
CACHE_DIR = DATA_DIR / "cache"

for directory in [DATA_DIR, DB_DIR, CACHE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Fontes de conhecimento organizadas por categoria
sources: Dict[str, Dict[str, Dict[str, str]]] = {
    "OWASP": {
        "owasp_top10": {
            "url": "https://raw.githubusercontent.com/OWASP/www-project-top-ten/main/2021/OWASP_Top_10-2021.md",
            "type": "markdown"
        },
        "owasp_api_top10": {
            "url": "https://raw.githubusercontent.com/OWASP/API-Security/main/2023/en/dist/owasp-api-top10-en.md",
            "type": "markdown"
        },
        "owasp_proactive_controls": {
            "url": "https://raw.githubusercontent.com/OWASP/www-project-proactive-controls/main/v3/OWASP_TOP_10_Proactive_Controls_v3.md",
            "type": "markdown"
        },
        "owasp_kubernetes_top10": {
            "url": "https://raw.githubusercontent.com/OWASP/www-project-kubernetes-top-ten/main/2022/en/dist/owasp-kubernetes-top-10.md",
            "type": "markdown"
        }
    },
    "NIST": {
        "nist_ssdf": {
            "url": "https://csrc.nist.gov/csrc/media/Publications/sp/800-218/final/documents/sp800-218.pdf",
            "type": "pdf"
        },
        "nist_container_security": {
            "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf",
            "type": "pdf"
        },
        "nist_devsecops": {
            "url": "https://csrc.nist.gov/csrc/media/Publications/sp/800-204c/draft/documents/sp800-204c-draft.pdf",
            "type": "pdf"
        }
    },
    "Cloud Native": {
        "cncf_whitepaper": {
            "url": "https://raw.githubusercontent.com/cncf/tag-security/main/security-whitepaper/v2/CNCF_security_whitepaper_v2.pdf",
            "type": "pdf"
        },
        "cncf_assessment": {
            "url": "https://raw.githubusercontent.com/cncf/tag-security/main/assessments/guide/en/doc.md",
            "type": "markdown"
        }
    },
    "CIS Benchmarks": {
        "cis_kubernetes": {
            "url": "https://raw.githubusercontent.com/aquasecurity/cloud-security-remediation-guides/main/en/kubernetes/cis-1.6.md",
            "type": "markdown"
        },
        "cis_docker": {
            "url": "https://raw.githubusercontent.com/docker/docker-bench-security/master/tests/1_host_configuration.sh",
            "type": "shell"
        }
    },
    "DevSecOps": {
        "devsecops_assessment": {
            "url": "https://raw.githubusercontent.com/devsecops/awesome-devsecops/master/README.md",
            "type": "markdown"
        },
        "gitlab_security": {
            "url": "https://raw.githubusercontent.com/gitlab/security-products/main/docs/index.md",
            "type": "markdown"
        },
        "github_security": {
            "url": "https://raw.githubusercontent.com/github/security-lab/main/SecurityLab.md",
            "type": "markdown"
        }
    },
    "Best Practices": {
        "containers_security": {
            "url": "https://raw.githubusercontent.com/docker/docker-bench-security/master/README.md",
            "type": "markdown"
        },
        "kubernetes_security": {
            "url": "https://raw.githubusercontent.com/kubernetes/security/main/security-practices.md",
            "type": "markdown"
        },
        "cloud_security": {
            "url": "https://raw.githubusercontent.com/aws/aws-security-services-best-practices/main/docs/en/guidelines.md",
            "type": "markdown"
        }
    }
}

class KnowledgeBaseLoader:
    def __init__(self):
        self.last_update = None
        self.download_stats = {"success": 0, "failed": 0}
        
    def download_docs(self) -> None:
        """
        Download documents from all configured sources
        """
        logger.info("Iniciando download dos documentos...")
        
        for category, category_sources in sources.items():
            logger.info(f"\nProcessando categoria: {category}")
            
            for doc_name, doc_info in category_sources.items():
                file_ext = ".pdf" if doc_info["type"] == "pdf" else ".md"
                file_path = DATA_DIR / category / f"{doc_name}{file_ext}"
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                if not file_path.exists():
                    logger.info(f"Baixando {doc_name}...")
                    try:
                        r = requests.get(doc_info["url"])
                        r.raise_for_status()
                        
                        with open(file_path, "wb") as f:
                            f.write(r.content)
                            
                        self.download_stats["success"] += 1
                        logger.info(f"✅ {doc_name} baixado com sucesso")
                        
                    except Exception as e:
                        self.download_stats["failed"] += 1
                        logger.error(f"❌ Erro ao baixar {doc_name}: {e}")
                else:
                    logger.info(f"📄 {doc_name} já existe localmente")

    def build_index(self) -> None:
        """
        Build the vector store index from downloaded documents
        """
        logger.info("\nConstruindo índice vetorial...")
        texts = []
        
        # Processar documentos por categoria
        for category_dir in DATA_DIR.iterdir():
            if category_dir.is_dir():
                logger.info(f"\nProcessando categoria: {category_dir.name}")
                
                for file in category_dir.glob("*"):
                    try:
                        content = file.read_text(errors="ignore")
                        
                        # Adicionar metadados ao conteúdo
                        metadata = {
                            "source": file.name,
                            "category": category_dir.name,
                            "type": "pdf" if file.suffix == ".pdf" else "markdown"
                        }
                        
                        texts.append({"content": content, "metadata": metadata})
                        logger.info(f"✅ Processado: {file.name}")
                        
                    except Exception as e:
                        logger.error(f"❌ Erro ao processar {file.name}: {e}")

        if not texts:
            logger.warning("⚠️ Nenhum documento encontrado para indexar!")
            return

        # Configurar o text splitter com parâmetros otimizados
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=1500,
            chunk_overlap=200,
            length_function=len,
            separators=["\n\n", "\n", " ", ""]
        )
        
        # Criar documentos com metadados
        docs = []
        for item in texts:
            chunks = splitter.create_documents(
                [item["content"]], 
                metadatas=[item["metadata"]] * len(splitter.split_text(item["content"]))
            )
            docs.extend(chunks)

        # Criar embeddings e persistir
        try:
            embeddings = OllamaEmbeddings(model="llama3")
            db = Chroma.from_documents(
                docs, 
                embeddings, 
                persist_directory=str(DB_DIR),
                collection_metadata={
                    "last_update": datetime.now().isoformat(),
                    "document_count": len(docs)
                }
            )
            db.persist()
            
            self.last_update = datetime.now()
            logger.info(f"\n✅ Base de conhecimento atualizada com sucesso!")
            logger.info(f"📊 Estatísticas:")
            logger.info(f"   - Documentos processados: {len(texts)}")
            logger.info(f"   - Chunks gerados: {len(docs)}")
            logger.info(f"   - Downloads com sucesso: {self.download_stats['success']}")
            logger.info(f"   - Downloads falhos: {self.download_stats['failed']}")
            
        except Exception as e:
            logger.error(f"❌ Erro ao criar índice vetorial: {e}")

def main():
    """
    Main function to run the knowledge base loader
    """
    try:
        loader = KnowledgeBaseLoader()
        loader.download_docs()
        loader.build_index()
    except KeyboardInterrupt:
        logger.info("\n ⚠️ Processo interrompido pelo usuário")
    except Exception as e:
        logger.error(f"❌ Erro fatal: {e}")

if __name__ == "__main__":
    main()
