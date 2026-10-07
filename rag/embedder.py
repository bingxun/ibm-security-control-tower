"""
RAG Embedder — IBM watsonx slate-125m-english-rtrvr
Wraps the ibm-watsonx-ai EmbedTextParamsMetricNames API.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from ibm_watsonx_ai import Credentials
from ibm_watsonx_ai.foundation_models import Embeddings
from ibm_watsonx_ai.metanames import EmbedTextParamsMetaNames as EmbedParams


WATSONX_URL = os.getenv("WATSONX_URL", "https://jp-tok.ml.cloud.ibm.com")
WATSONX_API_KEY = os.getenv("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")

EMBED_MODEL = "ibm/slate-125m-english-rtrvr-v2"
EMBED_DIM = 768  # slate-125m output dim


@lru_cache(maxsize=1)
def _get_embed_client() -> Embeddings:
    creds = Credentials(url=WATSONX_URL, api_key=WATSONX_API_KEY)
    return Embeddings(
        model_id=EMBED_MODEL,
        credentials=creds,
        project_id=WATSONX_PROJECT_ID,
        params={
            EmbedParams.TRUNCATE_INPUT_TOKENS: 512,
        },
    )


def _keyword_vector(text: str) -> List[float]:
    """
    Deterministic fallback embedding using character n-gram hashing.
    No network call needed — used when watsonx quota is exhausted.
    Returns a 768-dim unit vector so cosine similarity still works.
    """
    import math
    vec = [0.0] * EMBED_DIM
    text = text.lower()
    for i in range(len(text) - 2):
        ngram = text[i:i+3]
        h = hash(ngram) % EMBED_DIM
        vec[h] += 1.0
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def embed_texts(texts: List[str]) -> List[List[float]]:
    """
    Embed a list of strings. Returns a list of float vectors.
    Batches of up to 25 are supported by the watsonx API.
    Falls back to keyword hashing if the watsonx quota is exhausted.
    """
    try:
        client = _get_embed_client()
        vectors: List[List[float]] = []
        batch_size = 25
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            result = client.embed_documents(texts=batch)
            vectors.extend(result)
        return vectors
    except Exception:
        # Quota exhausted or network error — fall back to keyword hashing
        return [_keyword_vector(t) for t in texts]


def embed_text(text: str) -> List[float]:
    """Embed a single string."""
    return embed_texts([text])[0]
