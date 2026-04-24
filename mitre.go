package main

// MITRETechnique represents a single MITRE ATLAS technique.
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	OWASPIDs    []string `json:"owasp_ids"`
}

// mitreCatalog is a curated subset of MITRE ATLAS techniques relevant to LLM/AI attacks.
var mitreCatalog = []MITRETechnique{
	{
		ID:          "AML.T0051",
		Name:        "LLM Prompt Injection",
		Tactic:      "ML Attack Staging",
		Description: "An adversary crafts inputs that cause a large language model to deviate from its intended behavior, execute unauthorized instructions, or leak sensitive information.",
		OWASPIDs:    []string{"LLM01"},
	},
	{
		ID:          "AML.T0051.000",
		Name:        "Direct Prompt Injection",
		Tactic:      "ML Attack Staging",
		Description: "Adversary directly injects malicious instructions into the user-facing prompt, bypassing system constraints or extracting the system prompt.",
		OWASPIDs:    []string{"LLM01"},
	},
	{
		ID:          "AML.T0051.001",
		Name:        "Indirect Prompt Injection",
		Tactic:      "ML Attack Staging",
		Description: "Malicious instructions are embedded in external content (documents, web pages, tool outputs) that the LLM later processes, causing unintended actions.",
		OWASPIDs:    []string{"LLM01", "LLM07"},
	},
	{
		ID:          "AML.T0051.002",
		Name:        "LLM Plugin/Tool Compromise",
		Tactic:      "ML Attack Staging",
		Description: "Adversary abuses LLM tool-use capabilities or plugin interfaces (e.g., MCP, function calling) to invoke unauthorized operations or exfiltrate data.",
		OWASPIDs:    []string{"LLM07"},
	},
	{
		ID:          "AML.T0054",
		Name:        "LLM Jailbreak",
		Tactic:      "Defense Evasion",
		Description: "Adversary uses role-play personas, hypothetical framings, or adversarial suffixes to bypass safety filters and elicit harmful or restricted content from the model.",
		OWASPIDs:    []string{"LLM01"},
	},
	{
		ID:          "AML.T0020",
		Name:        "Poison Training Data",
		Tactic:      "ML Attack Staging",
		Description: "Adversary introduces malicious examples into training or fine-tuning datasets, causing the model to learn backdoors or biased behaviors.",
		OWASPIDs:    []string{"LLM03"},
	},
	{
		ID:          "AML.T0020.001",
		Name:        "RAG Vector Store Poisoning",
		Tactic:      "ML Attack Staging",
		Description: "Adversary injects malicious documents or embeddings into a retrieval-augmented generation (RAG) vector store, causing the LLM to return attacker-controlled responses.",
		OWASPIDs:    []string{"LLM03"},
	},
	{
		ID:          "AML.T0056",
		Name:        "LLM Data Leakage",
		Tactic:      "Exfiltration",
		Description: "Adversary crafts prompts that cause the model to reproduce training data verbatim, reveal system prompt contents, or disclose sensitive configuration details.",
		OWASPIDs:    []string{"LLM06"},
	},
	{
		ID:          "AML.T0048",
		Name:        "Erode ML Model Integrity",
		Tactic:      "Impact",
		Description: "Adversary manipulates an AI agent into taking actions beyond its intended scope — executing code, calling external APIs, modifying data — without explicit authorization.",
		OWASPIDs:    []string{"LLM08"},
	},
	{
		ID:          "AML.T0025",
		Name:        "Exfiltrate ML Model",
		Tactic:      "Exfiltration",
		Description: "Adversary extracts model weights, architecture details, or training hyperparameters through repeated inference queries, enabling offline attacks or IP theft.",
		OWASPIDs:    []string{"LLM10"},
	},
	{
		ID:          "AML.T0043",
		Name:        "Craft Adversarial Data",
		Tactic:      "ML Attack Staging",
		Description: "Adversary crafts specially constructed inputs — adversarial suffixes, homoglyph substitutions, base64 encoding, or Unicode tricks — to evade content filters.",
		OWASPIDs:    []string{"LLM01"},
	},
	{
		ID:          "AML.T0016",
		Name:        "Obtain Capabilities via LLM",
		Tactic:      "Reconnaissance",
		Description: "Adversary queries the model to discover its capabilities, tool integrations, API endpoints, token limits, and internal configuration — used to plan further attacks.",
		OWASPIDs:    []string{"LLM06", "LLM10"},
	},
	{
		ID:          "AML.T0040",
		Name:        "ML Model Inference API Access",
		Tactic:      "Initial Access",
		Description: "Adversary gains unauthenticated or over-privileged access to a model's inference API, enabling unrestricted querying for attacks such as extraction or injection.",
		OWASPIDs:    []string{"LLM07", "LLM10"},
	},
	{
		ID:          "AML.T0018",
		Name:        "Backdoor ML Model",
		Tactic:      "Persistence",
		Description: "Adversary embeds a hidden trigger in a model during fine-tuning or supply-chain compromise; the backdoor activates on specific inputs in production.",
		OWASPIDs:    []string{"LLM03"},
	},
}
