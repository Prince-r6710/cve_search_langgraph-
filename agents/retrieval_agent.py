# agents/retrieval_logic.py (Revised, adding fetch_cve_by_id)
import os
from typing import Dict, Any, List
from dotenv import load_dotenv
import re
import logging
import time

from utils.pinecone_client import get_pinecone_index
from utils.embeddings import generate_embedding

from sentence_transformers import CrossEncoder

import pinecone
import requests
import openai # Important for specific OpenAI errors in embeddings/LLM calls

load_dotenv()

logger = logging.getLogger(__name__)

class RetrievalAgent:
    def __init__(self):
        logger.info("Initializing RetrievalAgent...")
        self.reranker_model = None
        try:
            logger.info("Loading CrossEncoder re-ranker model (BAAI/bge-reranker-base)...")
            self.reranker_model = CrossEncoder('BAAI/bge-reranker-base')
            logger.info("CrossEncoder re-ranker model loaded successfully.")
        except Exception as e:
            logger.critical(f"Failed to load CrossEncoder model: {e}", exc_info=True)
            logger.critical("Please ensure 'sentence-transformers' is installed and the model can be downloaded.")
            self.reranker_model = None # Ensure it's explicitly None if load fails

        self.pinecone_index = self._get_pinecone_index_safely()

    def _get_pinecone_index_safely(self):
        try:
            index = get_pinecone_index()
            logger.debug("Pinecone index obtained successfully during initialization.")
            return index
        except Exception as e:
            logger.critical(f"Failed to get Pinecone index during initialization: {e}", exc_info=True)
            return None

    def _retry_operation(self, func, *args, max_attempts=3, delay_seconds=2, **kwargs):
        for attempt in range(1, max_attempts + 1):
            try:
                return func(*args, **kwargs)
            except (
                pinecone.core.exceptions.PineconeException,
                requests.exceptions.ConnectionError,
                openai.APITimeoutError, # Added OpenAI API specific errors
                openai.RateLimitError,
                Exception # Catch any other unexpected exceptions from the LLM/Embedding call
            ) as e:
                logger.warning(f"Attempt {attempt}/{max_attempts} failed for {func.__name__}: {e}")
                if attempt < max_attempts:
                    time.sleep(delay_seconds * (2 ** (attempt - 1)))
                else:
                    logger.error(f"All {max_attempts} attempts failed for {func.__name__}.", exc_info=True)
                    raise
            except Exception as e: # Catch any other unexpected errors
                logger.error(f"An unexpected error occurred during {func.__name__} on attempt {attempt}: {e}", exc_info=True)
                raise


    def fetch_cve_by_id(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Fetches a specific CVE by its ID.
        Assumes CVE IDs are stored as metadata 'cve_id' and vectors are searchable.
        A direct Pinecone `fetch` on ID might be more efficient if IDs are primary keys.
        For now, we'll do a semantic search with a tight filter for exact match.
        """
        logger.info(f"Attempting to fetch CVE details for ID: {cve_id}")
        if not self.pinecone_index:
            logger.error("Pinecone index not initialized. Cannot fetch CVE by ID.")
            return []

        try:
            embedding = generate_embedding(cve_id) # Embed the CVE ID itself
            
            # Query Pinecone for the specific CVE ID with a tight filter
            results = self._retry_operation(
                self.pinecone_index.query,
                vector=embedding, # Still use vector for query, but rely on filter for exactness
                top_k=1, # Only need 1 result
                include_metadata=True,
                filter={"cve_id": {"$eq": cve_id}} # Exact match filter
            )

            if results and results.get('matches'):
                # Iterate to find the exact match and format it
                for match in results['matches']:
                    if match.get('metadata', {}).get('cve_id') == cve_id:
                        metadata = match['metadata']
                        logger.info(f"Found exact match for CVE ID: {cve_id}")
                        return [{
                            "cve_id": metadata.get("cve_id"),
                            "description": metadata.get("text"),
                            "severity": metadata.get("severity"),
                            "score": metadata.get("cvss_score"),
                            "published_date": metadata.get("published_date"),
                            "pinecone_similarity_score": match.get("score")
                        }]
                logger.info(f"CVE ID {cve_id} not found in top_k matches despite filter.")
                return [] # No exact match in results
            logger.info(f"No matches found in Pinecone for CVE ID: {cve_id}")
            return []
        except Exception as e:
            logger.error(f"Error fetching CVE ID {cve_id}: {e}", exc_info=True)
            return []


    def retrieve_cves(self, parsed_query: Dict[str, Any], top_k: int = 5, initial_pinecone_k: int = 20) -> List[Dict[str, Any]]:
        """
        Retrieve and re-rank CVEs from Pinecone based on query embedding and metadata filters.
        This method is for general semantic searches, not direct ID lookups.
        
        Args:
            parsed_query: Dict containing parsed query fields like 'product', 'severity', 'year', etc.
            top_k: Number of final re-ranked results to return.
            initial_pinecone_k: Number of initial results to retrieve from Pinecone before re-ranking.
        
        Returns:
            List of re-ranked CVEs with metadata.
        """
        logger.info("Starting general CVE retrieval and re-ranking process...")
        
        if self.pinecone_index is None:
            logger.error("Pinecone index is not initialized. Cannot perform retrieval.")
            return []

        original_user_query = parsed_query.get("original_query", parsed_query.get("query", "CVE vulnerability"))
        query_text_for_embedding = parsed_query.get("product") or parsed_query.get("query") or "CVE vulnerability"
        
        logger.info(f"Query text for embedding generation: '{query_text_for_embedding}'")
        try:
            embedding = generate_embedding(query_text_for_embedding)
            logger.info("Embedding generated successfully.")
        except Exception as e:
            logger.error(f"Failed to generate embedding for query '{query_text_for_embedding}': {e}", exc_info=True)
            return []

        filter_dict = {}
        if "severity" in parsed_query and parsed_query["severity"]:
            filter_dict["severity"] = {"$eq": parsed_query["severity"].upper()} 
            logger.info(f"Applying severity filter: {parsed_query['severity']}")
        else:
            logger.info("No severity filter applied.")

        results = None
        try:
            logger.info(f"Sending query to Pinecone with top_k={initial_pinecone_k} and filter: {filter_dict if filter_dict else 'None'}...")
            results = self._retry_operation(
                self.pinecone_index.query,
                vector=embedding,
                top_k=initial_pinecone_k,
                include_metadata=True,
                filter=filter_dict if filter_dict else None
            )
            logger.info(f"Pinecone query completed. Got {len(results.get('matches', []))} raw matches.")

        except Exception as e:
            logger.error(f"Pinecone query failed after retries: {e}", exc_info=True)
            return []

        intermediate_results = []
        desired_year = parsed_query.get("year")
        if desired_year:
            logger.info(f"Applying Python-side year filter for: {desired_year}")

        for match in results.get('matches', []):
            metadata = match.get('metadata', {})
            published_date = metadata.get("published_date", "")
            
            if desired_year:
                if not published_date.startswith(str(desired_year)): 
                    logger.debug(f"Skipping CVE {metadata.get('cve_id')} due to year mismatch. Expected {desired_year}, got {published_date}.")
                    continue 
            
            formatted_result = {
                "cve_id": metadata.get("cve_id"),
                "description": metadata.get("text"),
                "severity": metadata.get("severity"),
                "score": metadata.get("cvss_score"),
                "published_date": published_date,
                "pinecone_similarity_score": match.get("score") 
            }
            intermediate_results.append(formatted_result)
        
        logger.info(f"After initial filtering, {len(intermediate_results)} candidates for re-ranking.")

        if not intermediate_results:
            logger.info("No results to re-rank after initial filtering.")
            return []

        if self.reranker_model is None:
            logger.warning("Re-ranker model not loaded. Skipping re-ranking and returning top_k from filtered Pinecone results.")
            sorted_by_pinecone = sorted(intermediate_results, key=lambda x: x.get('pinecone_similarity_score', 0), reverse=True)
            return sorted_by_pinecone[:top_k]

        reranker_pairs = []
        query_for_reranker = parsed_query.get("original_query", parsed_query.get("query", "CVE vulnerability"))

        for cve in intermediate_results:
            doc_text = f"CVE-ID: {cve.get('cve_id', 'N/A')}. Description: {cve.get('description', 'No description available.')}."
            if cve.get('severity'):
                 doc_text += f" Severity: {cve.get('severity')}."
            if cve.get('score'):
                 doc_text += f" CVSS Score: {cve.get('score')}."
            if cve.get('published_date'):
                 doc_text += f" Published: {cve.get('published_date')}."
            
            reranker_pairs.append([query_for_reranker, doc_text])

        logger.info(f"Sending {len(reranker_pairs)} pairs to re-ranker...")
        try:
            rerank_scores = self.reranker_model.predict(reranker_pairs)
            logger.info("Re-ranking completed.")
        except Exception as e:
            logger.error(f"Re-ranking prediction failed: {e}", exc_info=True)
            logger.warning("Skipping re-ranking due to error. Returning results sorted by Pinecone similarity.")
            sorted_by_pinecone = sorted(intermediate_results, key=lambda x: x.get('pinecone_similarity_score', 0), reverse=True)
            return sorted_by_pinecone[:top_k]

        scored_cves = []
        for i, cve in enumerate(intermediate_results):
            cve['rerank_score'] = rerank_scores[i]
            scored_cves.append(cve)
        
        final_ranked_cves = sorted(scored_cves, key=lambda x: x['rerank_score'], reverse=True)
        logger.info(f"Re-ranked results. Returning top {top_k}.")
        
        return final_ranked_cves[:top_k]

# Test cases for the class (unchanged, will use the new method in the graph)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    logger.info("--- Starting RetrievalAgent Class Test ---")

    retrieval_agent_instance = RetrievalAgent()

    # Test cases from previous versions (still valid)
    logger.info("\n--- Test Case 1: Critical Apache CVEs from 2018 ---")
    sample_query_1 = {
        "original_query": "List critical Apache vulnerabilities from 2018 and summarise their impact.",
        "product": "Apache",
        "severity": "CRITICAL",
        "year": "2018",
        "intent": "list"
    }
    results_1 = retrieval_agent_instance.retrieve_cves(sample_query_1, top_k=5, initial_pinecone_k=20)
    logger.info(f"Test Case 1 Results Count: {len(results_1)}")
    for idx, r in enumerate(results_1, 1):
        logger.info(f"  Result {idx}: CVE ID: {r.get('cve_id')}, Re-rank Score: {r.get('rerank_score'):.4f}, Severity: {r.get('severity')}, Published: {r.get('published_date')}, Pinecone Score: {r.get('pinecone_similarity_score'):.4f}")
    logger.info("-" * 50)

    logger.info("\n--- Test Case 3: Details for CVE-2023-45678 (example, now using fetch_cve_by_id) ---")
    # This will now use the dedicated fetch_cve_by_id in the graph
    # For direct testing of the method itself:
    results_direct_fetch = retrieval_agent_instance.fetch_cve_by_id("CVE-2023-45678")
    logger.info(f"Test Case Direct Fetch Results Count: {len(results_direct_fetch)}")
    for idx, r in enumerate(results_direct_fetch, 1):
        logger.info(f"  Result {idx}: CVE ID: {r.get('cve_id')}, Severity: {r.get('severity')}")
    logger.info("-" * 50)

    logger.info("--- RetrievalAgent Class Test Finished ---")