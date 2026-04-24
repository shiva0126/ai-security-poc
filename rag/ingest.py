#!/usr/bin/env python3
"""
RAG Ingest — loads docs/ into ChromaDB using Ollama nomic-embed-text embeddings.
Run once after ChromaDB and Ollama are healthy.
"""
import os, sys, json, pathlib, requests, time

CHROMA_HOST   = os.environ.get("CHROMA_HOST", "http://localhost:8000")
CHROMA_TOKEN  = os.environ.get("CHROMA_AUTH_TOKEN", "demo-chroma-token")
OLLAMA_BASE   = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
EMBED_MODEL   = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
COLLECTION    = os.environ.get("COLLECTION_NAME", "ai_security_kb")
DOCS_DIR      = pathlib.Path(__file__).parent / "docs"

HEADERS = {"Authorization": f"Bearer {CHROMA_TOKEN}", "Content-Type": "application/json"}

def get_embedding(text: str) -> list[float]:
    resp = requests.post(
        f"{OLLAMA_BASE}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=60
    )
    resp.raise_for_status()
    return resp.json()["embedding"]

def chroma_delete_collection(name: str):
    requests.delete(f"{CHROMA_HOST}/api/v2/tenants/default_tenant/databases/default_database/collections/{name}", headers=HEADERS)

def chroma_create_collection(name: str) -> str:
    resp = requests.post(
        f"{CHROMA_HOST}/api/v2/tenants/default_tenant/databases/default_database/collections",
        headers=HEADERS,
        json={"name": name, "metadata": {"hnsw:space": "cosine"}}
    )
    resp.raise_for_status()
    return resp.json()["id"]

def chroma_add(collection_id: str, ids, embeddings, documents, metadatas):
    resp = requests.post(
        f"{CHROMA_HOST}/api/v2/tenants/default_tenant/databases/default_database/collections/{collection_id}/add",
        headers=HEADERS,
        json={"ids": ids, "embeddings": embeddings, "documents": documents, "metadatas": metadatas}
    )
    resp.raise_for_status()

def chunk_text(text: str, chunk_size: int = 800, overlap: int = 100) -> list[str]:
    words = text.split()
    chunks, start = [], 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap
    return chunks

def wait_for_chroma():
    print("Waiting for ChromaDB...")
    for _ in range(30):
        try:
            r = requests.get(f"{CHROMA_HOST}/api/v2/heartbeat", timeout=5)
            if r.status_code == 200:
                print("ChromaDB ready")
                return
        except Exception:
            pass
        time.sleep(3)
    sys.exit("ChromaDB not reachable after 90s")

def wait_for_embed_model():
    print(f"Waiting for embedding model '{EMBED_MODEL}'...")
    for _ in range(20):
        try:
            r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
            models = [m["name"] for m in r.json().get("models", [])]
            if any(EMBED_MODEL in m for m in models):
                print(f"Model '{EMBED_MODEL}' ready")
                return
        except Exception:
            pass
        time.sleep(5)
    print(f"Warning: '{EMBED_MODEL}' not confirmed — attempting anyway")

def main():
    wait_for_chroma()
    wait_for_embed_model()

    print(f"\nRe-creating collection: {COLLECTION}")
    chroma_delete_collection(COLLECTION)
    collection_id = chroma_create_collection(COLLECTION)
    print(f"Collection ID: {collection_id}")

    all_ids, all_embeds, all_docs, all_meta = [], [], [], []
    chunk_idx = 0

    for doc_path in sorted(DOCS_DIR.glob("*.md")):
        print(f"\nIngesting: {doc_path.name}")
        text = doc_path.read_text()
        chunks = chunk_text(text)
        print(f"  {len(chunks)} chunks")

        for i, chunk in enumerate(chunks):
            print(f"  Embedding chunk {i+1}/{len(chunks)}...", end=" ", flush=True)
            emb = get_embedding(chunk)
            all_ids.append(f"{doc_path.stem}_chunk_{chunk_idx}")
            all_embeds.append(emb)
            all_docs.append(chunk)
            all_meta.append({"source": doc_path.name, "chunk": i})
            chunk_idx += 1
            print("done")

    print(f"\nAdding {len(all_ids)} chunks to ChromaDB...")
    batch_size = 50
    for i in range(0, len(all_ids), batch_size):
        chroma_add(
            collection_id,
            all_ids[i:i+batch_size],
            all_embeds[i:i+batch_size],
            all_docs[i:i+batch_size],
            all_meta[i:i+batch_size]
        )
    print(f"\nIngest complete. {len(all_ids)} chunks in collection '{COLLECTION}'")

if __name__ == "__main__":
    main()
