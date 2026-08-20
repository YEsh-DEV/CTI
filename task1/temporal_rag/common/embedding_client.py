"""
Embedding Client for TemporalRAG.
Wraps sentence-transformers with caching and lazy loading.
"""

import logging
from typing import List, Union
import numpy as np
from sentence_transformers import SentenceTransformer

from config.settings import EMBEDDING_MODEL, EMBEDDING_DIM

logger = logging.getLogger("temporal_rag.embedding")


class EmbeddingClient:
    """
    Singleton wrapper around SentenceTransformer.
    """
    _instance = None
    _model = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(EmbeddingClient, cls).__new__(cls)
        return cls._instance

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        if self._model is None:
            logger.info(f"Loading embedding model: {model_name}")
            self.model_name = model_name
            self._model = SentenceTransformer(model_name)
            logger.info(f"Model {model_name} loaded successfully (dim={EMBEDDING_DIM}).")

    def encode(
        self, 
        texts: Union[str, List[str]], 
        normalize_embeddings: bool = True,
        batch_size: int = 64,
        show_progress_bar: bool = False
    ) -> np.ndarray:
        """
        Encode text or list of texts into dense vectors.
        L2 normalized by default for fast inner-product cosine similarity.
        """
        is_single = isinstance(texts, str)
        if is_single:
            texts = [texts]

        if not texts:
            return np.empty((0, EMBEDDING_DIM), dtype=np.float32)

        embeddings = self._model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=show_progress_bar,
            normalize_embeddings=normalize_embeddings,
            convert_to_numpy=True
        )

        embeddings = embeddings.astype(np.float32)
        return embeddings[0] if is_single else embeddings

    @property
    def dimension(self) -> int:
        return self._model.get_sentence_embedding_dimension()
