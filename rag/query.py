#!/usr/bin/env python3
"""
CLI RAG query tool — run interactively or pass question as argument.
Usage:
  python3 query.py "What is OWASP LLM08 Excessive Agency?"
  python3 query.py  (interactive mode)
"""
import sys, os, json, requests

RAG_API = os.environ.get("RAG_API_URL", "http://localhost:9001")

def ask(question: str) -> None:
    resp = requests.post(f"{RAG_API}/query", json={"question": question, "n_results": 4}, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    print("\n" + "="*70)
    print(f"Q: {question}")
    print("="*70)
    print(f"\nA: {data['answer']}")
    print(f"\nSources: {', '.join(data['sources'])}")
    print(f"Context chunks used: {data['context_chunks']}")
    print("="*70 + "\n")

if len(sys.argv) > 1:
    ask(" ".join(sys.argv[1:]))
else:
    print("AI Security RAG — Interactive Mode (Ctrl+C to exit)\n")
    while True:
        try:
            q = input("Question: ").strip()
            if q:
                ask(q)
        except KeyboardInterrupt:
            print("\nBye")
            break
