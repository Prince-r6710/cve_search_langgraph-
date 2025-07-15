# interface/cli.py
# cve_langgraph_assignment/interface/cli.py

import os
import sys
import logging
from typing import Dict, Any

# Adjust path to import from graphs and agents directories
# Assuming this script is run from the project root or 'interface' directory.
# If running from project root, `python -m interface.cli` will work with relative imports.
# If running directly `python interface/cli.py` from `interface/`, then you might need sys.path.
# For simplicity, we'll assume running from project root or having PYTHONPATH configured.

from graphs.workflow_graph import build_workflow_graph, AgentState # Import AgentState for initial_state
# from utils.llm_client import get_llm_client # If agents need LLM directly

logger = logging.getLogger(__name__)
# Configure logging for CLI, can be adjusted
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def start_cli():
    """
    Initializes the LangGraph workflow and provides a command-line interface
    for users to query the CVE vulnerability system.
    """
    logger.info("Initializing CVE Vulnerability Analysis System...")
    try:
        # Build the graph once when the CLI starts
        app = build_workflow_graph()
        logger.info("System ready. Type your query or 'exit' to quit.")
    except Exception as e:
        logger.critical(f"Failed to initialize the system: {e}", exc_info=True)
        print("Error: Could not initialize the vulnerability analysis system. Please check logs.")
        sys.exit(1) # Exit if initialization fails

    while True:
        try:
            query = input("\nEnter your vulnerability query (or 'exit' to quit): ").strip()
            if query.lower() in ["exit", "quit"]:
                print("Exiting. Goodbye!")
                break

            if not query:
                print("Please enter a query.")
                continue

            # Prepare the initial state for the graph invocation
            initial_state: AgentState = {
                "query": query,
                "parsed_query": {},
                "retrieved_cves": [],
                "final_response": "",
                "error": "",
                "retrieval_type": ""
            }

            logger.info(f"Processing query: '{query}'")
            
            # Invoke the LangGraph workflow
            final_state: Dict[str, Any] = app.invoke(initial_state)

            # Extract and print the final response
            response = final_state.get('final_response', 'No response generated.')
            error_message = final_state.get('error', '')

            print("\n--- Response ---")
            print(response)
            if error_message:
                print(f"\n--- Workflow Error ---")
                print(error_message)
            print("----------------")

        except KeyboardInterrupt:
            print("\nExiting. Goodbye!")
            break
        except Exception as e:
            logger.error(f"An unexpected error occurred during query processing: {e}", exc_info=True)
            print("An error occurred during processing. Please try again or check the logs.")

if __name__ == "__main__":
    start_cli()