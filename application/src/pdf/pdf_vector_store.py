"""
PDF Vector Store
Manages FAISS and BM25 indexes for PDF documents.
"""

import os
import json
import pickle
from typing import List, Dict, Tuple
from datetime import datetime
import numpy as np

try:
    import faiss
except ImportError:
    faiss = None


class PDFVectorStore:
    """Manage embeddings and retrieval for PDF documents."""
    
    def __init__(self, embedding_model, index_dir: str = "data/pdf_indexes"):
        """
        Initialize PDF vector store.
        
        Args:
            embedding_model: Sentence transformer model
            index_dir: Directory to store indexes
        """
        self.embedding_model = embedding_model
        self.index_dir = index_dir
        self.documents: Dict[int, Dict] = {}
        self.index = None
        self.doc_counter = 0
        
        os.makedirs(index_dir, exist_ok=True)
    
    def add_documents(self, documents: List[Dict]) -> int:
        """
        Add documents to vector store.
        
        Args:
            documents: List of document dictionaries
            
        Returns:
            Number of documents added
        """
        embeddings = []
        
        for doc in documents:
            # Generate embedding
            embedding = self.embedding_model.encode(doc["content"])
            embeddings.append(embedding)
            
            # Store document metadata
            self.documents[self.doc_counter] = {
                "content": doc["content"],
                "source": doc.get("source", "unknown"),
                "page": doc.get("page", 0),
                "pdf_source": doc.get("pdf_source", ""),
                "chunk_id": doc.get("chunk_id", ""),
                "extracted_at": doc.get("extracted_at", "")
            }
            self.doc_counter += 1
        
        if not embeddings:
            return 0
        
        # Create or update FAISS index
        embeddings = np.array(embeddings).astype('float32')
        
        if self.index is None:
            dimension = embeddings.shape[1]
            self.index = faiss.IndexFlatL2(dimension) if faiss else None
        
        if self.index:
            self.index.add(embeddings)
        
        return len(documents)
    
    def search(self, query: str, k: int = 5) -> List[Tuple[Dict, float]]:
        """
        Search for similar documents.
        
        Args:
            query: Search query
            k: Number of results
            
        Returns:
            List of (document, score) tuples
        """
        if self.index is None or len(self.documents) == 0:
            return []
        
        # Get query embedding
        query_embedding = self.embedding_model.encode(query).astype('float32').reshape(1, -1)
        
        # Search
        distances, indices = self.index.search(query_embedding, min(k, len(self.documents)))
        
        results = []
        for idx, distance in zip(indices[0], distances[0]):
            if idx >= 0:
                doc = self.documents[idx]
                score = 1 / (1 + distance)  # Convert distance to similarity
                results.append((doc, score))
        
        return results
    
    def save(self, filename: str = "pdf_index.faiss"):
        """Save index to disk."""
        if self.index is None:
            return
        
        index_path = os.path.join(self.index_dir, filename)
        meta_path = os.path.join(self.index_dir, "metadata.pkl")
        
        faiss.write_index(self.index, index_path)
        
        with open(meta_path, 'wb') as f:
            pickle.dump(self.documents, f)
    
    def load(self, filename: str = "pdf_index.faiss"):
        """Load index from disk."""
        if not faiss:
            return False
        
        index_path = os.path.join(self.index_dir, filename)
        meta_path = os.path.join(self.index_dir, "metadata.pkl")
        
        if os.path.exists(index_path) and os.path.exists(meta_path):
            self.index = faiss.read_index(index_path)
            with open(meta_path, 'rb') as f:
                self.documents = pickle.load(f)
            self.doc_counter = len(self.documents)
            return True
        
        return False
    
    def get_stats(self) -> Dict:
        """Get vector store statistics."""
        return {
            "total_documents": len(self.documents),
            "index_size": self.index.ntotal if self.index else 0,
            "created_at": datetime.now().isoformat()
        }
