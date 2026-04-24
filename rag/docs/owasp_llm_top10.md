# OWASP LLM Top 10 — AI Security Knowledge Base

## LLM01: Prompt Injection
Attackers craft inputs that override the LLM's system instructions, hijacking the model's behavior. Direct injection embeds attacker instructions in the user prompt. Indirect injection embeds them in external content the model retrieves (documents, emails, web pages). Mitigation: input validation, privilege separation, constrained output handling.

## LLM02: Insecure Output Handling
LLM output is passed to downstream systems without sanitisation. Leads to XSS, SSRF, SSTI, RCE when output reaches browsers, code interpreters, or shell commands. Mitigation: treat all LLM output as untrusted, apply context-aware encoding.

## LLM03: Training Data Poisoning
Adversarial data inserted into training or fine-tuning datasets causes the model to learn backdoors, biases, or harmful behaviours. Attack is invisible at runtime — no CVE, no anomalous process. Mitigation: dataset provenance verification, cryptographic signing, anomaly detection during training.

## LLM04: Model Denial of Service
Crafted inputs consume disproportionate compute resources, degrading or crashing inference. Recursive context expansion and sponge examples are primary attack patterns. Mitigation: token budget limits, rate limiting per user/session, timeout enforcement.

## LLM05: Supply Chain Vulnerabilities
Third-party models, datasets, and plugins introduce risk. Malicious Hugging Face models, compromised Python packages, and backdoored fine-tuning datasets. Mitigation: model artifact scanning (Protect AI ModelScan), SBOM/AI-BOM, verified model registries.

## LLM06: Sensitive Information Disclosure
The model reveals training data, system prompts, API keys, or PII embedded in its context. Fine-tuned models can memorise and reproduce training data verbatim. Mitigation: differential privacy in training, output filtering, system prompt protection.

## LLM07: Insecure Plugin Design
Plugins and tools called by LLMs execute with excessive permissions. Insufficient input validation in plugin interfaces enables injection attacks. Mitigation: least-privilege tool design, input sanitisation at plugin boundary, explicit capability scoping.

## LLM08: Excessive Agency
Agents take unintended high-impact actions: deleting files, sending emails, executing code, calling external APIs. Root cause is combination of over-permissioned tools and insufficient guardrails on agent decisions. Mitigation: MCP tool allowlists, human-in-the-loop for destructive actions, rate limiting agent actions.

## LLM09: Overreliance
Operators and users trust LLM outputs without verification, leading to security decisions based on hallucinated CVEs, legal decisions on fabricated precedent, or medical decisions on invented dosages. Mitigation: mandatory human review for high-stakes outputs, output confidence scoring, citations requirement.

## LLM10: Model Theft
Systematic API queries reconstruct model weights or decision logic via model extraction attacks. Membership inference reveals whether specific data was in the training set (GDPR risk). Mitigation: rate limiting, query anomaly detection, output perturbation, differential privacy.
