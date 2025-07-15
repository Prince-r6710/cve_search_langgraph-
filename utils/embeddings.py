from openai import OpenAI
import os
import time
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def generate_embedding(text: str, model: str = "text-embedding-3-small", max_retries: int = 3) -> Optional[List[float]]:
    """
    Generate embedding for given text with retry logic and error handling.
    
    Args:
        text: Input text to embed
        model: OpenAI embedding model to use
        max_retries: Maximum number of retry attempts
    
    Returns:
        List of embedding values or None if failed
    """
    # Input validation
    if not text or not text.strip():
        print(f"[WARNING] Empty text provided for embedding")
        return None
    
    # Truncate text if too long (OpenAI has token limits)
    if len(text) > 8000:  # Conservative limit
        text = text[:8000]
        print(f"[WARNING] Text truncated to 8000 characters for embedding")
    
    for attempt in range(max_retries):
        try:
            response = client.embeddings.create(
                model=model,
                input=text
            )
            
            if response.data and len(response.data) > 0:
                embedding = response.data[0].embedding
                
                # Validate embedding
                if embedding and len(embedding) > 0:
                    return embedding
                else:
                    print(f"[ERROR] Empty embedding received for text: {text[:100]}...")
                    return None
            else:
                print(f"[ERROR] No embedding data in response")
                return None
                
        except Exception as e:
            error_msg = str(e)
            
            # Handle specific OpenAI errors
            if "rate limit" in error_msg.lower():
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"[WARNING] Rate limit hit, waiting {wait_time}s before retry {attempt + 1}/{max_retries}")
                time.sleep(wait_time)
                continue
            elif "invalid" in error_msg.lower():
                print(f"[ERROR] Invalid input for embedding: {error_msg}")
                return None
            elif "quota" in error_msg.lower():
                print(f"[ERROR] OpenAI quota exceeded: {error_msg}")
                return None
            else:
                print(f"[ERROR] Embedding generation failed (attempt {attempt + 1}/{max_retries}): {error_msg}")
                
                if attempt == max_retries - 1:
                    print(f"[ERROR] Failed to generate embedding after {max_retries} attempts")
                    return None
                else:
                    # Wait before retry
                    time.sleep(1 * (attempt + 1))
    
    return None

def generate_embeddings_batch(texts: List[str], model: str = "text-embedding-3-small", batch_size: int = 100) -> List[Optional[List[float]]]:
    """
    Generate embeddings for multiple texts in batches for efficiency.
    
    Args:
        texts: List of texts to embed
        model: OpenAI embedding model to use
        batch_size: Number of texts to process in each batch
    
    Returns:
        List of embeddings (same order as input texts)
    """
    if not texts:
        return []
    
    embeddings = []
    
    # Process in batches
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        
        try:
            response = client.embeddings.create(
                model=model,
                input=batch
            )
            
            # Extract embeddings in order
            batch_embeddings = []
            for j, data in enumerate(response.data):
                if data.embedding and len(data.embedding) > 0:
                    batch_embeddings.append(data.embedding)
                else:
                    print(f"[WARNING] Empty embedding for batch item {i + j}")
                    batch_embeddings.append(None)
            
            embeddings.extend(batch_embeddings)
            
        except Exception as e:
            print(f"[ERROR] Batch embedding failed for batch {i//batch_size + 1}: {str(e)}")
            # Fall back to individual processing for this batch
            for text in batch:
                embedding = generate_embedding(text, model)
                embeddings.append(embedding)
            
        # Small delay between batches to avoid rate limiting
        if i + batch_size < len(texts):
            time.sleep(0.1)
    
    return embeddings

def get_embedding_dimension(model: str = "text-embedding-3-small") -> int:
    """
    Get the dimension of embeddings for a given model.
    
    Args:
        model: OpenAI embedding model
    
    Returns:
        Embedding dimension
    """
    model_dimensions = {
        "text-embedding-3-small": 1536,
        "text-embedding-3-large": 3072,
        "text-embedding-ada-002": 1536
    }
    
    return model_dimensions.get(model, 1536)

def test_embedding_connection():
    """Test if embedding service is working properly"""
    test_text = "This is a test sentence for embedding."
    
    try:
        embedding = generate_embedding(test_text)
        if embedding:
            print(f"[INFO] ✅ Embedding service working. Dimension: {len(embedding)}")
            return True
        else:
            print(f"[ERROR] ❌ Embedding service not working - no embedding returned")
            return False
    except Exception as e:
        print(f"[ERROR] ❌ Embedding service test failed: {str(e)}")
        return False

# Test the service when module is imported
if __name__ == "__main__":
    print("Testing embedding service...")
    test_embedding_connection()
    
    # Test batch processing
    test_texts = [
        "This is the first test sentence.",
        "This is the second test sentence.",
        "This is the third test sentence."
    ]
    
    print("\nTesting batch embedding...")
    batch_embeddings = generate_embeddings_batch(test_texts)
    print(f"Generated {len([e for e in batch_embeddings if e is not None])} embeddings out of {len(test_texts)}")