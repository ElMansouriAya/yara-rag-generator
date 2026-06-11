"""
Extended Knowledge Base
Merges original dataset and PDF document retrieval results.
"""

from typing import List, Dict, Tuple, Optional
from .knowledge_base import KnowledgeBase


class ExtendedKnowledgeBase:
    """Combine original KB with PDF documents."""
    
    def __init__(self, original_kb: KnowledgeBase, pdf_vector_store=None):
        """
        Initialize extended KB.
        
        Args:
            original_kb: Original KnowledgeBase instance
            pdf_vector_store: PDFVectorStore instance (optional)
        """
        self.original_kb = original_kb
        self.pdf_vector_store = pdf_vector_store
    
    def retrieve(self, query: str, k: int = 10, 
                 pdf_weight: float = 0.3) -> List[Dict]:
        """
        Retrieve from both original KB and PDFs.
        
        Args:
            query: Search query
            k: Total number of results
            pdf_weight: Weight for PDF results (0-1)
            
        Returns:
            List of retrieved documents
        """
        # Retrieve from original KB
        kb_results = self.original_kb.retrieve(query, k)
        
        # Retrieve from PDFs if available
        pdf_results = []
        if self.pdf_vector_store:
            pdf_search_results = self.pdf_vector_store.search(query, k)
            pdf_results = [
                {
                    **doc,
                    "score": score * pdf_weight,
                    "source_type": "pdf"
                }
                for doc, score in pdf_search_results
            ]
        
        # Merge and rank by score
        all_results = kb_results + pdf_results
        all_results.sort(key=lambda x: x.get("score", 0), reverse=True)
        
        return all_results[:k]
    
    def add_pdf_documents(self, documents: List[Dict]) -> Dict:
        """
        Add PDF documents to extended KB.
        
        Args:
            documents: List of PDF documents
            
        Returns:
            Operation status
        """
        if not self.pdf_vector_store:
            return {
                "success": False,
                "error": "PDF vector store not initialized"
            }
        
        added = self.pdf_vector_store.add_documents(documents)
        
        return {
            "success": True,
            "documents_added": added
        }
    
    def get_stats(self) -> Dict:
        """Get combined statistics."""
        stats = {
            "original_kb": self.original_kb.get_stats(),
            "pdf_store": self.pdf_vector_store.get_stats() if self.pdf_vector_store else None,
            "mode": "extended"
        }
        return stats
