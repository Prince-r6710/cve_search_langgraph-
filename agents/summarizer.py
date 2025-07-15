# cve_langgraph_assignment/agents/summarizer_agent.py

import json
import logging
import os
from typing import List, Dict, Any

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv
from utils.prompts import (
    SUMMARIZER_SYSTEM_PROMPT,
    SUMMARIZER_HUMAN_PROMPT_TEMPLATE
)

# --- NEW IMPORT: For handling numpy.float32 ---
try:
    import numpy as np
except ImportError:
    np = None
    logging.warning("Numpy not installed. If your data contains numpy.float32, "
                    "you might encounter JSON serialization errors. "
                    "Install with `pip install numpy`.")
# --- END NEW IMPORT ---

# Load environment variables for OPENAI_API_KEY
load_dotenv()

logger = logging.getLogger(__name__)

class SummarizerAgent:
    def __init__(self, llm_model_name: str = "gpt-3.5-turbo"):
        # Initialize OpenAI LLM directly here
        openai_api_key = os.getenv("OPENAI_API_KEY")
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set. Please set it in your .env file.")

        self.llm = ChatOpenAI(
            model=llm_model_name,
            temperature=0.0,
            timeout=30
            # api_key=openai_api_key # Pass API key explicitly if not set as env var LANGCHAIN_API_KEY / OPENAI_API_KEY
        )

        self.base_prompt = ChatPromptTemplate.from_messages([
            ("system", SUMMARIZER_SYSTEM_PROMPT),
            ("human", SUMMARIZER_HUMAN_PROMPT_TEMPLATE)
        ])
        self.chain = self.base_prompt | self.llm
        logger.info(f"SummarizerAgent initialized with model: {llm_model_name}")

    # --- NEW METHOD: To convert non-JSON serializable types ---
    def _convert_non_serializable(self, obj):
        """
        Recursively converts non-JSON serializable types (like numpy.float32)
        to standard Python native types.
        """
        if isinstance(obj, list):
            return [self._convert_non_serializable(elem) for elem in obj]
        elif isinstance(obj, dict):
            return {k: self._convert_non_serializable(v) for k, v in obj.items()}
        # Check for numpy types and convert them
        elif np is not None and isinstance(obj, (np.float32, np.float64, np.int32, np.int64)):
            return obj.item() # .item() converts numpy scalar to Python scalar
        # Add other specific types if you encounter them (e.g., torch.Tensor, Decimal, datetime)
        # elif isinstance(obj, torch.Tensor): # if using PyTorch
        #     return obj.item() if obj.numel() == 1 else obj.tolist()
        # elif isinstance(obj, datetime.datetime): # if using datetime objects
        #     return obj.isoformat()
        return obj
    # --- END NEW METHOD ---

    def summarize_cves(self, cves: List[Dict[str, Any]], parsed_query: Dict[str, Any]) -> str:
        if not cves:
            return "No specific CVEs were found to summarize based on your query."

        # --- NEW: Process CVEs to ensure JSON serializability ---
        processed_cves = self._convert_non_serializable(cves)
        cve_data_json_str = json.dumps(processed_cves, indent=2)
        # --- END NEW ---
        
        original_query = parsed_query.get("original_query", "User query not available.")
        intent = parsed_query.get("intent", "general_info")

        logger.info(f"Summarizing {len(cves)} CVEs with intent '{intent}' for query: '{original_query}'")
        try:
            response = self.chain.invoke({
                "cve_data": cve_data_json_str,
                "original_query": original_query,
                "intent": intent
            })
            summary = response.content
            logger.info(f"Summary generated (first 100 chars): {summary[:min(len(summary), 100)]}...")
            return summary
        except Exception as e:
            logger.error(f"Error summarizing CVEs: {e}", exc_info=True)
            return f"An error occurred while generating the summary: {e}"

# Example usage (for testing, not part of the main workflow)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    print("--- Starting SummarizerAgent Test ---")
    
    summarizer_agent = SummarizerAgent(llm_model_name="gpt-3.5-turbo") 
    
    # --- MODIFIED MOCK CVEs for testing the float32 issue ---
    # We'll simulate a numpy.float32 value for cvssv3_score
    # In a real scenario, this would come from your Pinecone/vector DB retrieval
    if np is not None:
        mock_cves = [
            {
                "cve_id": "CVE-2023-12345",
                "description": "A critical buffer overflow vulnerability in AcmeCorp Widget v1.0 allows remote attackers to execute arbitrary code.",
                "product": "AcmeCorp Widget",
                "severity": "CRITICAL",
                "cvssv3_score": np.float32(9.8), # Simulating float32 from retrieval
                "hasKev": False,
                "published_date": "2023-03-15"
            },
            {
                "cve_id": "CVE-2023-67890",
                "description": "An information disclosure vulnerability in ExampleSoft Gadget v2.1 could allow an attacker to read sensitive files.",
                "product": "ExampleSoft Gadget",
                "severity": "HIGH",
                "cvssv3_score": np.float32(7.5), # Simulating float32 from retrieval
                "hasKev": True,
                "published_date": "2023-06-20"
            }
        ]
    else:
        # Fallback if numpy is not installed, use standard floats
        mock_cves = [
            {
                "cve_id": "CVE-2023-12345",
                "description": "A critical buffer overflow vulnerability in AcmeCorp Widget v1.0 allows remote attackers to execute arbitrary code.",
                "product": "AcmeCorp Widget",
                "severity": "CRITICAL",
                "cvssv3_score": 9.8,
                "hasKev": False,
                "published_date": "2023-03-15"
            },
            {
                "cve_id": "CVE-2023-67890",
                "description": "An information disclosure vulnerability in ExampleSoft Gadget v2.1 could allow an attacker to read sensitive files.",
                "product": "ExampleSoft Gadget",
                "severity": "HIGH",
                "cvssv3_score": 7.5,
                "hasKev": True,
                "published_date": "2023-06-20"
            }
        ]
    # --- END MODIFIED MOCK CVEs ---

    mock_parsed_query = {
        "query": "Summarize recent critical vulnerabilities for risk analysis.",
        "original_query": "Summarize recent critical vulnerabilities for risk analysis.",
        "intent": "risk_analysis"
    }

    summary = summarizer_agent.summarize_cves(mock_cves, mock_parsed_query)
    logger.info("\n--- Generated Summary ---")
    logger.info(summary)
    logger.info("--- SummarizerAgent Test Finished ---")