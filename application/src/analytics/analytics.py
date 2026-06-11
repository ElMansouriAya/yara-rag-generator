"""
Analytics Module
Track PDF uploads, retrievals, and generation metrics.
"""

import os
import json
from typing import Dict, List
from datetime import datetime


class Analytics:
    """Track analytics for PDF operations."""
    
    def __init__(self, analytics_file: str = "data/analytics.json"):
        """
        Initialize analytics tracker.
        
        Args:
            analytics_file: Path to analytics JSON file
        """
        self.analytics_file = analytics_file
        self.data = self._load()
    
    def _load(self) -> Dict:
        """Load existing analytics."""
        if os.path.exists(self.analytics_file):
            with open(self.analytics_file, 'r') as f:
                return json.load(f)
        
        return {
            "pdf_uploads": [],
            "pdf_stats": {
                "total_pdfs": 0,
                "total_documents": 0,
                "total_size": 0
            },
            "retrievals": {
                "total": 0,
                "from_pdf": 0,
                "from_kb": 0
            }
        }
    
    def _save(self):
        """Save analytics to file."""
        os.makedirs(os.path.dirname(self.analytics_file) or '.', exist_ok=True)
        with open(self.analytics_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def track_pdf_upload(self, filename: str, num_docs: int, 
                        file_size: int, pages: int, metadata: Dict = None) -> Dict:
        """
        Track PDF upload event with detailed metrics.
        
        Args:
            filename: Name of PDF file
            num_docs: Number of documents/chunks created
            file_size: Size in bytes
            pages: Number of pages
            metadata: Additional metadata from processor
            
        Returns:
            Upload record
        """
        record = {
            "timestamp": datetime.now().isoformat(),
            "filename": filename,
            "documents": num_docs,
            "size_bytes": file_size,
            "pages": pages,
            "status": "indexed",
            "extraction_time": metadata.get("extraction_time", 0) if metadata else 0,
            "processing_time": metadata.get("processing_time", 0) if metadata else 0,
            "embedding_count": num_docs,
            "vector_indexed": True
        }
        
        self.data["pdf_uploads"].append(record)
        
        # Update stats
        self.data["pdf_stats"]["total_pdfs"] += 1
        self.data["pdf_stats"]["total_documents"] += num_docs
        self.data["pdf_stats"]["total_size"] += file_size
        
        self._save()
        
        return record
    
    def track_retrieval(self, from_pdf: bool = False) -> None:
        """
        Track retrieval event.
        
        Args:
            from_pdf: Whether retrieval was from PDF
        """
        self.data["retrievals"]["total"] += 1
        
        if from_pdf:
            self.data["retrievals"]["from_pdf"] += 1
        else:
            self.data["retrievals"]["from_kb"] += 1
        
        self._save()
    
    def get_pdf_stats(self) -> Dict:
        """Get PDF statistics."""
        return {
            "total_pdfs": self.data["pdf_stats"]["total_pdfs"],
            "total_documents": self.data["pdf_stats"]["total_documents"],
            "total_size_mb": round(self.data["pdf_stats"]["total_size"] / (1024**2), 2),
            "uploads": self.data["pdf_uploads"][-10:]  # Last 10 uploads
        }
    
    def get_retrieval_stats(self) -> Dict:
        """Get retrieval statistics."""
        total = self.data["retrievals"]["total"]
        
        return {
            "total_retrievals": total,
            "from_pdf": self.data["retrievals"]["from_pdf"],
            "from_kb": self.data["retrievals"]["from_kb"],
            "pdf_percentage": round(
                (self.data["retrievals"]["from_pdf"] / total * 100) if total > 0 else 0, 
                1
            )
        }
    
    def get_all_stats(self) -> Dict:
        """Get all analytics."""
        return {
            "pdf_stats": self.get_pdf_stats(),
            "retrieval_stats": self.get_retrieval_stats()
        }


class AnalyticsManager:
    """Singleton for analytics access."""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = Analytics()
        return cls._instance
