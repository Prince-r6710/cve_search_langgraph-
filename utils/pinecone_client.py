# utils/pinecone_client.py

import os
from pinecone import Pinecone
from dotenv import load_dotenv
load_dotenv()

def get_pinecone_index():
    # Initialize Pinecone client
    api_key = os.getenv("PINECONE_API_KEY")
    index_name = os.getenv("PINECONE_INDEX_NAME")

    if not api_key or not index_name:
        raise ValueError("PINECONE_API_KEY and PINECONE_INDEX_NAME must be set in .env file.")

    pc = Pinecone(api_key=api_key)

    # Connect to existing index
    index = pc.Index(index_name)
    return index

# Quick test when running standalone
if __name__ == "__main__":
    index = get_pinecone_index()
    print("[INFO] ✅ Pinecone index connection successful.")
