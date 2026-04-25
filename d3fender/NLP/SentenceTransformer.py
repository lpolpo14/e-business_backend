"""
The main sentence transformer class used for plain text input handling.
"""

import os
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["TRANSFORMERS_VERBOSITY"] = "error"

from transformers.utils import logging as transformers_logging

transformers_logging.set_verbosity_error()

from sentence_transformers import SentenceTransformer
import numpy as np

class DefensesSentenceTransformer:
    def __init__(self,
                 capabilities_registry: dict,
                 controls_registry: dict,
                 model_name: str = "all-MiniLM-L6-v2"):
        """
            The initialization method for CapabilitiesSentenceTransformer.
            It retrieves every capability mentioned in the given registry, and encodes/embeds
            each entry of the texts list.
        Args:
            registry: The registry JSON that contains all the defined defensive capabilities.
            model_name: The model used to encode/embed the text.
        """

        self.model = SentenceTransformer(model_name)
        self.cap_ids = []
        texts = []

        for capability in capabilities_registry.get("capabilities", []):
            cap_id = capability["id"]
            title = capability["title"]
            category = capability["category"]
            aliases = capability["aliases"]
            text = f"{title}. Category: {category}. Aliases: " + ", ".join(aliases)
            self.cap_ids.append(cap_id)
            texts.append(text)

        for control in controls_registry.get("controls", []):
            cap_id = control["id"]
            title = control["title"]
            category = control["category"]
            aliases = control["aliases"]
            text = f"{title}. Category: {category}. Aliases: " + ", ".join(aliases)
            self.cap_ids.append(cap_id)
            texts.append(text)
        embeddings = self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        self.embeddings = embeddings

    def query(self, query: str, top_k : int = 5):
        """
            Used to query for a specific capability.
        Args:
            query: The given input/query to search for similar capabilities.
            top_k: How many

        Returns:
            Top K most similar capabilities based on the provided query.

        """
        embedding = self.model.encode([query], convert_to_numpy=True, normalize_embeddings=True)[0]
        scores = self.embeddings @ embedding # Cosine Similarity through Matrix Multiplication
        idx = np.argsort(scores)[::-1][:top_k]
        return [(self.cap_ids[i], float(scores[i])) for i in idx]



