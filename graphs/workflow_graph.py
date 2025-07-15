# workflow_graph.py (Revised for explicit CVE ID path)
import os
from typing import TypedDict, List, Dict, Any
from dotenv import load_dotenv
import logging
from langgraph.graph import StateGraph, END, START
from langgraph.graph.message import add_messages

# Import your agents
from agents.query_parser import QueryParserAgent
from agents.retrieval_agent import RetrievalAgent # Already imports the class
from agents.summarizer import SummarizerAgent

load_dotenv()

# Configure logging for the workflow graph
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- 1. Define the Graph State ---
class AgentState(TypedDict):
    """
    Represents the state of our graph.
    """
    query: str
    parsed_query: Dict[str, Any]
    retrieved_cves: List[Dict[str, Any]]
    final_response: str
    error: str
    # Added for more specific error messaging
    retrieval_type: str # 'general_search' or 'cve_id_lookup'

# --- 2. Initialize Agent Instances ---
query_parser_agent = QueryParserAgent()
retrieval_agent = RetrievalAgent()
summarizer_agent = SummarizerAgent()

# --- 3. Define Nodes (Agent Functions) ---

def parse_query_node(state: AgentState) -> Dict[str, Any]:
    logger.info(f"Executing parse_query_node for query: {state['query']}")
    try:
        parsed_data = query_parser_agent.parse(state['query'])
        logger.debug(f"Parsed query: {parsed_data}")
        return {"parsed_query": parsed_data, "error": ""}
    except Exception as e:
        logger.error(f"Error in parse_query_node: {e}", exc_info=True)
        return {"error": f"Failed to parse query: {e}"}

def fetch_cve_by_id_node(state: AgentState) -> Dict[str, Any]:
    """
    Node to fetch a specific CVE by ID if identified by the parser.
    """
    if state.get("error"):
        logger.warning("Skipping fetch_cve_by_id_node due to previous error.")
        return state

    cve_id = state['parsed_query'].get("cve_id")
    if not cve_id:
        logger.error("fetch_cve_by_id_node called without a 'cve_id' in parsed_query. This should not happen with correct routing.")
        return {"error": "Internal error: Missing CVE ID for direct lookup."}

    logger.info(f"Executing fetch_cve_by_id_node for CVE ID: {cve_id}")
    try:
        cves = retrieval_agent.fetch_cve_by_id(cve_id)
        logger.debug(f"Fetched {len(cves)} CVEs for ID {cve_id}.")
        return {"retrieved_cves": cves, "error": "", "retrieval_type": "cve_id_lookup"}
    except Exception as e:
        logger.error(f"Error in fetch_cve_by_id_node for {cve_id}: {e}", exc_info=True)
        return {"error": f"Failed to retrieve CVE ID {cve_id}: {e}", "retrieval_type": "cve_id_lookup"}

def retrieve_cves_node(state: AgentState) -> Dict[str, Any]:
    """
    Node to perform general CVE retrieval based on the parsed query.
    """
    if state.get("error"):
        logger.warning("Skipping retrieve_cves_node due to previous error.")
        return state

    logger.info(f"Executing retrieve_cves_node for general query: {state['parsed_query']}")
    try:
        cves = retrieval_agent.retrieve_cves(state['parsed_query'])
        logger.debug(f"Retrieved {len(cves)} CVEs for general query.")
        return {"retrieved_cves": cves, "error": "", "retrieval_type": "general_search"}
    except Exception as e:
        logger.error(f"Error in retrieve_cves_node: {e}", exc_info=True)
        return {"error": f"Failed to retrieve CVEs: {e}", "retrieval_type": "general_search"}

# In graphs/workflow_graph.py

def summarize_cves_node(state: AgentState) -> Dict[str, Any]: # It should return Dict[str, Any] or AgentState
    if state.get("error"):
        logger.warning("Skipping summarize_cves_node due to previous error.")
        return state # If there's an error, just return the existing state

    logger.info("Executing summarize_cves_node.")
    
    # Extract necessary info from the current state
    retrieved_cves = state['retrieved_cves']
    parsed_query = state['parsed_query'] # Get the whole parsed_query dictionary

    try:
        # Call the summarizer agent's method
        # Ensure your summarizer_agent is correctly initialized globally or passed in
        summary = summarizer_agent.summarize_cves(retrieved_cves, parsed_query)
        logger.debug(f"Generated summary: {summary[:100]}...")

        # !!! THE FIX IS HERE !!!
        # This is where you need to update the 'final_response' key in the state
        # And importantly, return the MODIFIED state.
        return {"final_response": summary, "error": ""} # Return a dictionary of updates

    except Exception as e:
        logger.error(f"Error in summarize_cves_node: {e}", exc_info=True)
        return {"error": f"Failed to summarize CVEs: {e}", "final_response": "An error occurred while trying to summarize the vulnerabilities. Please try again later."}

def format_no_results_node(state: AgentState) -> Dict[str, Any]:
    """
    Node to format a response when no CVEs are found or an error occurred.
    Provides more specific messages based on the nature of the issue.
    """
    logger.info("Executing format_no_results_node.")
    
    if state.get("error"):
        specific_error = state['error']
        if "Failed to parse query" in specific_error:
            return {"final_response": f"I had trouble understanding your request: {specific_error}. Please try rephrasing your query.", "error": ""}
        elif "Failed to retrieve CVE ID" in specific_error:
            return {"final_response": f"I couldn't find any details for the specific CVE ID you provided: {state['parsed_query'].get('cve_id', 'N/A')}. Please double-check the ID.", "error": ""}
        elif "Failed to retrieve CVEs" in specific_error:
             return {"final_response": f"I encountered an issue while searching for vulnerabilities: {specific_error}. Please try again later or refine your search.", "error": ""}
        else: # Generic error
            return {"final_response": f"An unexpected error occurred during processing: {specific_error}. Please try again or rephrase your query.", "error": ""}
    else:
        # No CVEs found without an explicit error (e.g., semantic search yielded nothing)
        if state.get("retrieval_type") == "cve_id_lookup" and state.get("parsed_query", {}).get("cve_id"):
            return {"final_response": f"I couldn't find any details for CVE ID: {state['parsed_query']['cve_id']}. It might not exist or isn't in our database.", "error": ""}
        return {"final_response": "I couldn't find any relevant vulnerabilities based on your query. Please try rephrasing or providing more details.", "error": ""}

# --- 4. Define Conditional Edges (Routing Logic) ---

def route_after_parse(state: AgentState) -> str:
    """
    Determines the next step after query parsing.
    - If parsing failed, go to 'format_no_results'.
    - If a specific CVE ID is found, go to 'fetch_cve_by_id'.
    - Else (general query), go to 'retrieve_cves'.
    """
    if state.get("error"):
        logger.info("Routing to 'format_no_results' due to parsing error.")
        return "format_no_results"
    
    if state['parsed_query'].get("cve_id"):
        logger.info(f"Routing to 'fetch_cve_by_id_node' for specific CVE ID: {state['parsed_query']['cve_id']}.")
        return "fetch_cve_by_id"
    
    logger.info("Routing to 'retrieve_cves' for general query.")
    return "retrieve_cves"

def route_after_retrieval(state: AgentState) -> str:
    """
    Determines the next step after CVE retrieval (either general or by ID).
    - If retrieval failed or no CVEs found, go to 'format_no_results'.
    - Else, go to 'summarize_cves'.
    """
    if state.get("error") or not state.get("retrieved_cves"):
        logger.info("Routing to 'format_no_results' due to retrieval error or no CVEs found.")
        return "format_no_results"
    logger.info("Routing to 'summarize_cves' after successful retrieval.")
    return "summarize_cves"


# --- 5. Build the LangGraph ---

def build_workflow_graph():
    """
    Builds and compiles the LangGraph workflow.
    """
    workflow = StateGraph(AgentState)

    # Add nodes for each step
    workflow.add_node("parse_query", parse_query_node)
    workflow.add_node("fetch_cve_by_id", fetch_cve_by_id_node) # New node
    workflow.add_node("retrieve_cves", retrieve_cves_node) # Renamed to be specific for general search
    workflow.add_node("summarize_cves", summarize_cves_node)
    workflow.add_node("format_no_results", format_no_results_node)

    # Set the entry point
    workflow.set_entry_point("parse_query")

    # Define edges
    # After parsing, decide if there was an error, specific CVE ID, or general search
    workflow.add_conditional_edges(
        "parse_query",
        route_after_parse,
        {
            "format_no_results": "format_no_results",
            "fetch_cve_by_id": "fetch_cve_by_id", # New path
            "retrieve_cves": "retrieve_cves"
        }
    )

    # After specific CVE ID fetch, decide if results or no results
    workflow.add_conditional_edges(
        "fetch_cve_by_id",
        route_after_retrieval, # Re-use routing, as it checks for errors/empty results
        {
            "format_no_results": "format_no_results",
            "summarize_cves": "summarize_cves"
        }
    )

    # After general retrieval, decide if results or no results
    workflow.add_conditional_edges(
        "retrieve_cves",
        route_after_retrieval, # Re-use routing
        {
            "format_no_results": "format_no_results",
            "summarize_cves": "summarize_cves"
        }
    )

    # From summarization, always go to END
    workflow.add_edge("summarize_cves", END)

    # From format_no_results, always go to END
    workflow.add_edge("format_no_results", END)

    # Compile the graph
    app = workflow.compile()
    logger.info("LangGraph workflow compiled.")
    return app

# In your __main__ block of workflow_graph.py
if __name__ == "__main__":
    # ... (rest of your setup) ...
    app = build_workflow_graph()

    # Define test queries
    test_queries = [
        "List all critical Apache vulnerabilities published in 2018 and summarize their potential impact."
    ]
 

    for i, query in enumerate(test_queries):
        print(f"\n--- Running Test Case {i+1}: '{query}' ---")
        logger.info(f"Invoking graph with query: '{query}'")
        
        # Initialize the state correctly for invoke
        initial_state = AgentState(
            query=query,
            parsed_query={},
            retrieved_cves=[],
            final_response="",
            error="",
            retrieval_type="" 
        )

        try:
            # Only need one of these. `app.invoke` is sufficient for testing.
            # Remove the `for s in app.stream(...)` loop if you only want the final output.
            # It's currently redundant and might cause issues if not handled carefully.
            # If you want to see streaming, then you should process 's' directly.
            # For simply getting the final result, remove the stream loop.
            # for s in app.stream({"query": query}):
            #     if "__end__" not in s:
            #         # print(s) 
            #         pass
            
            final_state = app.invoke(initial_state) # Pass the initial_state here

            # --- CRITICAL FIX HERE ---
            print(f"Final Response: {final_state.get('final_response', 'No response generated.')}")
            if final_state['error']:
                print(f"Workflow Error: {final_state['error']}")
            print("-" * 70)

        except Exception as e:
            logger.critical(f"Unhandled exception during graph invocation for query '{query}': {e}", exc_info=True)
            print(f"An unhandled error occurred during processing: {e}")
            print("-" * 70)

    logger.info("--- LangGraph Workflow Testing Completed ---")
