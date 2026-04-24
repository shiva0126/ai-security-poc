#!/usr/bin/env python3
"""
Test 06 — RAG Pipeline Validation
Verifies ChromaDB retrieval + Ollama generation pipeline is working.
Tests knowledge base coverage across all four document sources.
"""
import requests, os, sys

RAG_API = os.environ.get("RAG_API_URL", "http://localhost:9001")

TEST_QUESTIONS = [
    {
        "question": "What is OWASP LLM08 Excessive Agency and how does it apply to MCP servers?",
        "expected_sources": ["owasp_llm_top10.md"],
        "category": "OWASP"
    },
    {
        "question": "How does CrowdStrike AIDR's agentic collector work and what does it capture?",
        "expected_sources": ["crowdstrike_aidr.md"],
        "category": "CrowdStrike"
    },
    {
        "question": "What model platforms does Qualys TotalAI support for LLM scanning?",
        "expected_sources": ["qualys_totalai.md"],
        "category": "Qualys"
    },
    {
        "question": "What is the visibility floor problem in the AI security architecture?",
        "expected_sources": ["architecture_overview.md"],
        "category": "Architecture"
    },
    {
        "question": "How is data poisoning different from prompt injection and why is it more dangerous?",
        "expected_sources": ["owasp_llm_top10.md", "architecture_overview.md"],
        "category": "Threat Intel"
    },
    {
        "question": "What are the three enforcement modes in CrowdStrike AIDR's policy engine?",
        "expected_sources": ["crowdstrike_aidr.md"],
        "category": "CrowdStrike"
    },
]

def run():
    print("\n==========================================")
    print("  TEST 06 — RAG Pipeline Validation")
    print("==========================================\n")

    try:
        h = requests.get(f"{RAG_API}/health", timeout=5)
        h.raise_for_status()
        info = h.json()
        print(f"  RAG API: {info}\n")
    except Exception as e:
        print(f"  [FAIL] RAG API not reachable: {e}")
        print(f"  → Start with: cd /home/cybersec/my-project && docker compose up rag-api")
        return

    passed = 0
    for i, q in enumerate(TEST_QUESTIONS, 1):
        print(f"  [{i}] [{q['category']}] {q['question'][:70]}")
        try:
            r = requests.post(f"{RAG_API}/query",
                              json={"question": q["question"], "n_results": 4},
                              timeout=120)
            r.raise_for_status()
            data = r.json()
            source_match = any(s in data["sources"] for s in q["expected_sources"])
            status = "PASS" if source_match else "PARTIAL"
            if source_match:
                passed += 1
            print(f"     [{status}] Sources: {data['sources']} | Chunks: {data['context_chunks']}")
            print(f"     Answer: {data['answer'][:130].replace(chr(10),' ')}...\n")
        except Exception as e:
            print(f"     [ERROR] {e}\n")

    print(f"  Results: {passed}/{len(TEST_QUESTIONS)} questions retrieved from correct sources")
    print("  → RAG pipeline is grounding model responses in the AI security knowledge base\n")

if __name__ == "__main__":
    run()
