# src/preprocessing/document_loader.py

from pathlib import Path
from typing import List, Dict
import json, csv
import pdfplumber
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings("ignore", message="CropBox missing from /Page, defaulting to MediaBox")

SUPPORTED_EXTENSIONS = {
    '.pdf': 'pdf',
    '.txt': 'text',
    '.html': 'html',
    '.htm': 'html',
    '.yara': 'yara',
    '.yar': 'yara',
    '.json': 'json',
    '.csv': 'csv',
    '.md': 'markdown',
    '.docx': 'docx',
}

def load_all_documents(base_dir: Path) -> List[Dict]:
    """
    Parcourt tous les sous-dossiers et charge les documents.
    """
    documents = []
    
    for folder in base_dir.iterdir():
        if not folder.is_dir():
            continue
            
        folder_name = folder.name
        print(f"📁 Traitement du dossier: {folder_name}")
        
        for file_path in folder.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                doc = load_single_file(file_path, folder_name)
                if doc:
                    documents.append(doc)
    
    return documents

def load_single_file(file_path: Path, source_folder: str) -> Dict:
    """Charge un fichier selon son type."""
    ext = file_path.suffix.lower()
    doc_type = SUPPORTED_EXTENSIONS.get(ext, 'unknown')
    
    try:
        if doc_type == 'pdf':
            text = extract_pdf(file_path)
        elif doc_type == 'html':
            text = extract_html(file_path)
        elif doc_type == 'yara':
            text = file_path.read_text(encoding='utf-8', errors='ignore')
        elif doc_type == 'json':
            return load_json_file(file_path, source_folder)
        elif doc_type == 'csv':
            return load_csv_file(file_path, source_folder)
        elif doc_type in ('text', 'markdown'):
            text = file_path.read_text(encoding='utf-8', errors='ignore')
        else:
            return None
        
        return {
            'id': generate_doc_id(file_path),
            'source_folder': source_folder,
            'filename': file_path.name,
            'file_path': str(file_path),
            'doc_type': doc_type,
            'raw_text': text,
            'metadata': {'size': file_path.stat().st_size}
        }
        
    except Exception as e:
        print(f" Erreur sur {file_path}: {e}")
        return None

def extract_pdf(file_path: Path) -> str:
    """Extrait le texte d'un PDF avec PyMuPDF (plus rapide, moins de warnings)."""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(str(file_path))
        text = "\n".join(page.get_text() for page in doc)
        doc.close()
        return text
    except ImportError:
        # Fallback sur pdfplumber si PyMuPDF non installé
        import pdfplumber
        with pdfplumber.open(file_path) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)

def extract_html(file_path: Path) -> str:
    
    soup = BeautifulSoup(file_path.read_text(encoding='utf-8'), 'html.parser')
    # Supprimer scripts et styles
    for tag in soup(['script', 'style']):
        tag.decompose()
    return soup.get_text(separator='\n')

def load_json_file(file_path: Path, source_folder: str) -> Dict:
    """Charge un fichier JSON déjà structuré."""
    data = json.loads(file_path.read_text(encoding='utf-8'))
    return {
        'id': generate_doc_id(file_path),
        'source_folder': source_folder,
        'filename': file_path.name,
        'file_path': str(file_path),
        'doc_type': 'json',
        'raw_text': json.dumps(data, ensure_ascii=False),
        'structured_data': data,  # Déjà parsé !
        'metadata': {}
    }

def load_csv_file(file_path: Path, source_folder: str) -> Dict:
    """Charge un CSV et le convertit en liste de dicts."""
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return {
        'id': generate_doc_id(file_path),
        'source_folder': source_folder,
        'filename': file_path.name,
        'file_path': str(file_path),
        'doc_type': 'csv',
        'raw_text': file_path.read_text(encoding='utf-8'),
        'structured_data': rows,
        'metadata': {'row_count': len(rows)}
    }

def generate_doc_id(file_path: Path) -> str:
    """Génère un ID unique basé sur le chemin."""
    from hashlib import md5
    return md5(str(file_path).encode()).hexdigest()[:8]