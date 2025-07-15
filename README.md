# CVE LangGraph Vulnerability Query System

## 🚀 Overview

This project implements a **Retrieval-Augmented Generation (RAG) pipeline** to query and summarize Common Vulnerabilities and Exposures (CVEs).

It uses:

- **LangGraph** for modular workflow orchestration
- **Pinecone** for vector-based semantic retrieval
- **OpenAI LLMs** for parsing, re-ranking, and summarization

---

## 📝 **Workflow Documentation**

### 🔄 **End-to-End Flow**

1. **User Query Input**

   The CLI collects a natural language query such as:  List all critical Apache vulnerabilities published in 2018.

2. **Query Parsing**

- `QueryParserAgent` uses an LLM to parse input into structured fields:
  - `product`: Apache
  - `severity`: critical
  - `published_year`: 2018

3. **Routing Logic (LangGraph)**

- **If CVE ID detected:**\
  Calls `fetch_cve_by_id_node` to retrieve the specific CVE directly.
- **Else (General query):**\
  Calls `retrieve_cves_node` for semantic retrieval.

4. **Retrieval & Re-ranking**

- **Vector Retrieval:**\
  Uses Pinecone to retrieve top relevant CVEs.
- **CrossEncoder Re-ranking:**\
  Re-ranks retrieved CVEs for final relevance ordering.

5. **Summarization**

- `SummarizerAgent` uses an LLM to summarize retrieved CVEs into a concise, human-readable response.

6. **Error Handling**

- Each node returns an `error` field if it fails.
- Conditional edges route to `format_no_results_node` when parsing or retrieval errors occur, ensuring graceful user feedback.

---

📂 **Folder Structure**

      cve_langgraph_assignment/
         ├── agents/
         │   ├── query_parser.py
         │   ├── retrieval_agent.py
         │   └── summarizer_agent.py
         │
         ├── graphs/
         │   └── workflow_graph.py
         │
         ├── interface/
         │   └── cli.py
         │
         ├── scripts/
         │   ├── download.py          # Downloads CVE data zip files from NVD
         │   ├── unzip.py             # Unzips downloaded data files
         │   └── embed_and_ingest.py  # Embeds cleaned data and ingests into Pinecone
         │
         ├── utils/
         │   ├── parse_clean.py       # Parses and cleans unzipped CVE JSON files
         │   ├── embedding.py         # Embedding logic for CVE data
         │   ├── pinecone_init.py     # Pinecone client initialization
         │   └── prompts.py           # Prompt templates for agents
         │
         │
         ├── requirements.txt
         └── README.md


---

## 🔧 **Installation & Setup**

1. **Clone the repository**

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

```
2. ***Create virtual environment & install dependencies**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. ***Configure environment variables**
```bash
OPENAI_API_KEY=your_openai_key
PINECONE_API_KEY=your_pinecone_key
PINECONE_ENVIRONMENT=your_pinecone_env
```

▶️ Running the CLI
```bash
python -m interface.cli
```
You will be prompted:
     Enter your vulnerability query (or 'exit' to quit): ex : Summarize recent critical Windows vulnerabilities.
    

Key Design Highlights  :

LangGraph orchestration: Modular agent execution with conditional routing.

Error handling: Nodes return structured errors; routing logic manages fallback.

CrossEncoder re-ranking: Improves retrieval relevance before summarization.

Extensibility: Easy to add fallback to NVD API for live data or additional analysis nodes.











