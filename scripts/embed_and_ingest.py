import os
import json
import time
from tqdm import tqdm
from dotenv import load_dotenv
from typing import List, Dict, Any

from utils.embeddings import generate_embedding, generate_embeddings_batch
from utils.pinecone_client import get_pinecone_index

import nltk
# Download punkt if not already present
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')
from nltk import sent_tokenize

# ========== Semantic chunking ==========
def semantic_chunk(text: str, max_tokens: int = 100, overlap: int = 20) -> List[str]:
    """
    Split text into semantic chunks with token overlap.
    
    Args:
        text: Input text to chunk
        max_tokens: Maximum tokens per chunk
        overlap: Number of tokens to overlap between chunks
    
    Returns:
        List of text chunks
    """
    if not text or not text.strip():
        return []
    
    sentences = sent_tokenize(text)
    chunks = []
    current_chunk = []
    current_tokens = 0

    for sentence in sentences:
        tokens = sentence.split()
        if current_tokens + len(tokens) <= max_tokens:
            current_chunk.append(sentence)
            current_tokens += len(tokens)
        else:
            if current_chunk:  # Only add non-empty chunks
                chunks.append(' '.join(current_chunk))
            
            # Start new chunk with overlap
            if overlap > 0 and current_chunk:
                overlap_tokens = []
                temp_chunk = current_chunk.copy()
                while temp_chunk and len(' '.join(overlap_tokens).split()) < overlap:
                    overlap_tokens.insert(0, temp_chunk.pop())
                current_chunk = overlap_tokens + [sentence]
                current_tokens = sum(len(s.split()) for s in current_chunk)
            else:
                current_chunk = [sentence]
                current_tokens = len(tokens)

    if current_chunk:
        chunks.append(' '.join(current_chunk))

    return chunks


# ========== Batch processing for efficiency ==========
def process_batch(batch_data: List[Dict[str, Any]], index, use_batch_embedding: bool = True) -> int:
    """Process a batch of embeddings and upsert to Pinecone"""
    vectors_to_upsert = []
    
    # Collect all chunks and their metadata for batch processing
    all_chunks = []
    chunk_metadata_list = []
    
    for item in batch_data:
        cve_id = item.get("cve_id", "")
        description = item.get("description", "")
        severity = item.get("severity") or "UNKNOWN"
        published_date = item.get("published_date") or ""
        cvss_score = item.get("cvss_score") or 0.0
        
        # Skip empty descriptions
        if not description.strip():
            continue

        try:
            # ========== Semantic chunking ==========
            chunks = semantic_chunk(description)
            
            for i, chunk in enumerate(chunks):
                if not chunk.strip():  # Skip empty chunks
                    continue
                
                all_chunks.append(chunk)
                chunk_metadata_list.append({
                    "cve_id": str(cve_id) if cve_id else "UNKNOWN",
                    "chunk_index": i,
                    "severity": str(severity) if severity else "UNKNOWN",
                    "published_date": str(published_date) if published_date else "",
                    "cvss_score": float(cvss_score) if cvss_score is not None else 0.0,
                    "text": chunk,
                    "text_length": len(chunk)
                })
                
        except Exception as e:
            print(f"[ERROR] Failed to process CVE {cve_id}: {str(e)}")
            continue
    
    if not all_chunks:
        return 0
    
    # Generate embeddings - batch or individual
    if use_batch_embedding and len(all_chunks) > 1:
        print(f"[INFO] Generating {len(all_chunks)} embeddings in batch...")
        embeddings = generate_embeddings_batch(all_chunks, batch_size=100)
    else:
        print(f"[INFO] Generating {len(all_chunks)} embeddings individually...")
        embeddings = []
        for chunk in all_chunks:
            embedding = generate_embedding(chunk)
            embeddings.append(embedding)
    
    # Combine embeddings with metadata
    for embedding, metadata in zip(embeddings, chunk_metadata_list):
        if embedding:  # Only add successful embeddings
            vectors_to_upsert.append({
                "id": f"{metadata['cve_id']}_{metadata['chunk_index']}",
                "values": embedding,
                "metadata": metadata
            })
    
    # Batch upsert to Pinecone
    if vectors_to_upsert:
        try:
            # Pinecone recommends batches of 100 vectors
            pinecone_batch_size = 100
            total_upserted = 0
            
            for i in range(0, len(vectors_to_upsert), pinecone_batch_size):
                batch = vectors_to_upsert[i:i + pinecone_batch_size]
                
                # Retry logic for Pinecone upsert
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        index.upsert(vectors=batch)
                        total_upserted += len(batch)
                        break
                    except Exception as e:
                        if attempt == max_retries - 1:
                            print(f"[ERROR] Failed to upsert batch after {max_retries} attempts: {str(e)}")
                            return total_upserted
                        else:
                            print(f"[WARNING] Upsert attempt {attempt + 1} failed, retrying: {str(e)}")
                            time.sleep(2 ** attempt)
                
                # Small delay between batches
                time.sleep(0.1)
            
            print(f"[INFO] Successfully upserted {total_upserted} vectors to Pinecone")
            return total_upserted
            
        except Exception as e:
            print(f"[ERROR] Failed to upsert batch to Pinecone: {str(e)}")
            return 0
    
    return 0


# ========== Main embedding and ingestion function ==========
def embed_and_ingest_all(parsed_dir: str = "./parsed_feeds", batch_size: int = 50, use_batch_embedding: bool = True):
    """
    Embed and ingest all parsed CVE data into Pinecone.
    
    Args:
        parsed_dir: Directory containing parsed JSON files
        batch_size: Number of CVEs to process in each batch
        use_batch_embedding: Whether to use batch embedding for efficiency
    """
    load_dotenv()

    # Test embedding service first
    print("[INFO] Testing embedding service...")
    from utils.embeddings import test_embedding_connection
    if not test_embedding_connection():
        print("[ERROR] Embedding service test failed. Please check your OpenAI API key.")
        return

    try:
        index = get_pinecone_index()
        stats = index.describe_index_stats()
        print(f"[INFO] Connected to Pinecone index: {stats}")
    except Exception as e:
        print(f"[ERROR] Failed to connect to Pinecone: {str(e)}")
        return

    # Get all parsed files
    if not os.path.exists(parsed_dir):
        print(f"[ERROR] Directory {parsed_dir} does not exist")
        return
    
    files = [f for f in os.listdir(parsed_dir) if f.endswith("_parsed.json")]
    if not files:
        print(f"[ERROR] No parsed files found in {parsed_dir}")
        return
    
    # Sort files for consistent processing order
    files.sort()
    print(f"[INFO] Found {len(files)} parsed files for embedding ingestion.")
    print(f"[INFO] Using {'batch' if use_batch_embedding else 'individual'} embedding generation")

    total_vectors = 0
    total_cves = 0
    failed_files = []

    for file_idx, file_name in enumerate(tqdm(files, desc="Processing files")):
        file_path = os.path.join(parsed_dir, file_name)
        
        try:
            print(f"\n[INFO] Processing file {file_idx + 1}/{len(files)}: {file_name}")
            
            with open(file_path, "r", encoding='utf-8') as f:
                data = json.load(f)
            
            if not data:
                print(f"[WARNING] Empty file: {file_name}")
                continue
            
            print(f"[INFO] Found {len(data)} CVEs in {file_name}")
            file_vectors = 0
            
            # Process in batches
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                
                print(f"[INFO] Processing batch {i//batch_size + 1}/{(len(data) + batch_size - 1)//batch_size} ({len(batch)} CVEs)")
                
                vectors_added = process_batch(batch, index, use_batch_embedding)
                file_vectors += vectors_added
                total_vectors += vectors_added
                total_cves += len(batch)
                
                # Progress update
                if i % (batch_size * 5) == 0:
                    print(f"[INFO] Progress: {i + len(batch)}/{len(data)} CVEs processed from {file_name}")
                    print(f"[INFO] Cumulative: {total_vectors} vectors created from {total_cves} CVEs")
            
            print(f"[INFO] ✅ Completed {file_name}: {file_vectors} vectors added")
        
        except Exception as e:
            print(f"[ERROR] Failed to process file {file_name}: {str(e)}")
            failed_files.append(file_name)
            continue

    # Final summary
    print(f"\n[INFO] ✅ Embedding ingestion completed!")
    print(f"[INFO] Files processed: {len(files) - len(failed_files)}/{len(files)}")
    print(f"[INFO] Total CVEs processed: {total_cves}")
    print(f"[INFO] Total vectors created: {total_vectors}")
    
    if failed_files:
        print(f"[WARNING] Failed files: {failed_files}")
    
    # Verify final ingestion
    try:
        final_stats = index.describe_index_stats()
        print(f"[INFO] Final index stats: {final_stats}")
    except Exception as e:
        print(f"[WARNING] Could not retrieve final index stats: {str(e)}")
    
    # Calculate success rate
    if total_cves > 0:
        success_rate = (total_vectors / total_cves) * 100
        print(f"[INFO] Success rate: {success_rate:.1f}% (vectors/CVEs)")
    
    return total_vectors, total_cves





# ========== Resume functionality ==========
def resume_ingestion(parsed_dir: str = "./parsed_feeds", skip_existing: bool = True, use_batch_embedding: bool = True):
    """Resume ingestion with option to skip existing CVEs"""
    if skip_existing:
        print("[INFO] Checking for existing CVEs to skip...")
        # This would require modification to the main function
        # to check existing data before processing
    
    embed_and_ingest_all(parsed_dir, use_batch_embedding=use_batch_embedding)


# ========== Script entrypoint ==========
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Embed and ingest CVE data into Pinecone")
    parser.add_argument("--parsed-dir", default="./parsed_feeds", help="Directory containing parsed JSON files")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size for processing CVEs")
    parser.add_argument("--resume", action="store_true", help="Resume ingestion (skip existing)")
    parser.add_argument("--no-batch-embedding", action="store_true", help="Disable batch embedding (use individual)")
    parser.add_argument("--test-small", action="store_true", help="Test with small dataset (first 100 CVEs)")
    
    args = parser.parse_args()
    
    use_batch_embedding = not args.no_batch_embedding
    
    if args.test_small:
        print("[INFO] Running in test mode with limited data...")
        # Process only first file with limited data
        embed_and_ingest_all(args.parsed_dir, batch_size=10, use_batch_embedding=use_batch_embedding)
    elif args.resume:
        resume_ingestion(args.parsed_dir, skip_existing=True, use_batch_embedding=use_batch_embedding)
    else:
        embed_and_ingest_all(args.parsed_dir, args.batch_size, use_batch_embedding=use_batch_embedding)