# cve_langgraph_assignment/agents/query_parser.py

import json
import logging
import os # <-- Need os to get API key
from typing import Dict, Any

from langchain_openai import ChatOpenAI # <--- Direct import
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser # <--- Still use JsonOutputParser
from dotenv import load_dotenv # <--- Need dotenv here
from utils.prompts import (
    QUERY_PARSER_SYSTEM_PROMPT,
    QUERY_PARSER_HUMAN_PROMPT_TEMPLATE
)


load_dotenv()

logger = logging.getLogger(__name__)

class QueryParserAgent:
    """
    A class to parse natural language queries into a structured JSON format
    for cybersecurity vulnerability analysis, using ChatOpenAI directly.
    """
    def __init__(self, llm_model_name: str = "gpt-3.5-turbo"):
        # Initialize OpenAI LLM directly here
        openai_api_key = os.getenv("OPENAI_API_KEY")
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set. Please set it in your .env file.")

        self.llm = ChatOpenAI(
            model=llm_model_name, 
            temperature=0.0,
            timeout=10,
            api_key=openai_api_key 
        )

        # Define parsing prompt template
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", QUERY_PARSER_SYSTEM_PROMPT),
            ("human", QUERY_PARSER_HUMAN_PROMPT_TEMPLATE)
        ])
        
        # Use JsonOutputParser in the chain
        self.parser = JsonOutputParser()
        self.chain = self.prompt | self.llm | self.parser
        
        logger.info(f"QueryParserAgent initialized with model: {llm_model_name}")

    def parse(self, question: str) -> Dict[str, Any]:
        """
        Parses a natural language question into a structured dictionary using an LLM.

        Args:
            question: The user's natural language query string.

        Returns:
            A dictionary containing the parsed query parameters and the original query.
            Includes an 'error' key if parsing fails.
        """
        logger.info(f"Parsing question: '{question}'")
        
        try:
            # Invoke the LCEL chain directly; it handles prompt formatting and JSON parsing
            parsed_json = self.chain.invoke({"question": question}) 
            
            # Ensure all expected keys are present even if null/false for consistency in AgentState
            default_parsed_query = {
                "cve_id": None, "product": None, "version": None, "severity": None,
                "year": None, "hasKev": False, "intent": "unknown"
            }
            # Update defaults with parsed data, ensuring all expected keys are there
            final_parsed_data = {**default_parsed_query, **parsed_json}
            
            final_parsed_data["original_query"] = question # Add original query for context
            
            logger.info(f"Parsed successfully: {json.dumps(final_parsed_data, indent=2)}")
            return final_parsed_data

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM output as JSON. Error: {e}", exc_info=True)
            # log the raw LLM output here for debugging if chain.invoke fails before parsing
            return {
                "cve_id": None, "product": None, "version": None,
                "severity": None, "year": None, "hasKev": False,
                "intent": "unknown", 
                "error": f"Failed to parse LLM response as valid JSON: {e}",
                "original_query": question
            }
        except Exception as e:
            logger.error(f"An unexpected error occurred during LLM chain invocation: {e}", exc_info=True)
            return {
                "cve_id": None, "product": None, "version": None,
                "severity": None, "year": None, "hasKev": False,
                "intent": "unknown", 
                "error": f"LLM chain invocation failed: {str(e)}",
                "original_query": question
            }

# --- Main function for direct testing of the QueryParserAgent ---
if __name__ == "__main__":
    # Configure basic logging for the test run if not already configured globally
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    print("--- Starting QueryParserAgent Test ---")
    
    # Instantiate the QueryParserAgent
    parser = QueryParserAgent(llm_model_name="gpt-3.5-turbo") 

    # Define a list of test queries
    test_queries = [
        "List all critical Apache vulnerabilities published in 2024 known to be exploited.",
        "Summarize recent high severity OpenSSL bugs.",
        "Tell me details about CVE-2023-12345.",
        "Are there any medium severity vulnerabilities in Python?",
        "What are the top 3 vulnerabilities for Windows from 2023?",
        "General info on networking device vulnerabilities.",
        "Show me low severity issues in nginx.",
        "Compare recent vulnerabilities in Linux and macOS.",
        "What is the risk associated with older Java versions?",
        "A very vague query with no clear intent."
    ]

    # Iterate through each test query and print the parsed result
    for i, query in enumerate(test_queries):
        logger.info(f"\n--- Test Case {i+1} ---")
        logger.info(f"Processing Query: '{query}'")
        
        parsed_result = parser.parse(query)
        
        logger.info("Parsed Result JSON:")
        logger.info(json.dumps(parsed_result, indent=2)) 
        logger.info("-" * 50) # Separator for test cases

    logger.info("--- QueryParserAgent Test Finished ---")