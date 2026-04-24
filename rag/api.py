#!/usr/bin/env python3
"""
RAG API — FastAPI endpoint for retrieval-augmented generation.
Queries ChromaDB for context, passes to Ollama, returns grounded answer.
"""
import os, json, requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

CHROMA_HOST  = os.environ.get("CHROMA_HOST", "http://localhost:8000")
CHROMA_TOKEN = os.environ.get("CHROMA_AUTH_TOKEN", "demo-chroma-token")
OLLAMA_BASE  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
EMBED_MODEL  = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
COLLECTION   = os.environ.get("COLLECTION_NAME", "ai_security_kb")

HEADERS = {"Authorization": f"Bearer {CHROMA_TOKEN}", "Content-Type": "application/json"}

app = FastAPI(title="AI Security RAG API", version="1.0")

def get_collection_id() -> str:
    r = requests.get(f"{CHROMA_HOST}/api/v2/tenants/default_tenant/databases/default_database/collections/{COLLECTION}", headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json()["id"]

def embed(text: str) -> list[float]:
    r = requests.post(f"{OLLAMA_BASE}/api/embeddings",
                      json={"model": EMBED_MODEL, "prompt": text}, timeout=30)
    r.raise_for_status()
    return r.json()["embedding"]

def retrieve(query_embedding: list[float], n_results: int = 4) -> list[dict]:
    cid = get_collection_id()
    r = requests.post(
        f"{CHROMA_HOST}/api/v2/tenants/default_tenant/databases/default_database/collections/{cid}/query",
        headers=HEADERS,
        json={"query_embeddings": [query_embedding], "n_results": n_results,
              "include": ["documents", "metadatas", "distances"]},
        timeout=30
    )
    r.raise_for_status()
    data = r.json()
    results = []
    for doc, meta, dist in zip(data["documents"][0], data["metadatas"][0], data["distances"][0]):
        results.append({"document": doc, "source": meta.get("source"), "distance": dist})
    return results

def generate(prompt: str) -> str:
    r = requests.post(
        f"{OLLAMA_BASE}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=120
    )
    r.raise_for_status()
    return r.json()["response"]

class QueryRequest(BaseModel):
    question: str
    n_results: int = 4

class QueryResponse(BaseModel):
    answer: str
    sources: list[str]
    context_chunks: int

@app.get("/health")
def health():
    return {"status": "ok", "model": OLLAMA_MODEL, "collection": COLLECTION}

@app.post("/query", response_model=QueryResponse)
def query(req: QueryRequest):
    try:
        q_emb = embed(req.question)
        chunks = retrieve(q_emb, req.n_results)
        context = "\n\n---\n\n".join(c["document"] for c in chunks)
        sources = list({c["source"] for c in chunks})
        prompt = f"""You are an AI security expert assistant for the AI Security POC.
Answer the question using ONLY the context provided below. Be specific and cite the source document.

CONTEXT:
{context}

QUESTION: {req.question}

ANSWER:"""
        answer = generate(prompt)
        return QueryResponse(answer=answer.strip(), sources=sources, context_chunks=len(chunks))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/collections")
def list_collections():
    r = requests.get(f"{CHROMA_HOST}/api/v2/tenants/default_tenant/databases/default_database/collections", headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.json()
