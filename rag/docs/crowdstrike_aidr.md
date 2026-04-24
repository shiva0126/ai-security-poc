# CrowdStrike Falcon AIDR — Knowledge Base

## Overview
CrowdStrike Falcon AI Detection and Response (AIDR) reached General Availability on December 15, 2025. It is the industry's first unified platform securing every layer of enterprise AI from development through workforce usage. Built on the existing Falcon platform using a single lightweight sensor and single console.

## Collector Types
- **Browser Collector**: Managed browser extensions capturing employee AI tool usage — prompts, responses, PII in AI interactions with ChatGPT, Claude, Copilot, Gemini.
- **Gateway Collector**: Network proxies, LiteLLM, Kong, Azure API Management. Captures all AI API traffic at the network ingress layer.
- **Application Collector**: SDK or direct API integration capturing AI-powered application prompt/response flows.
- **Agentic Collector**: MCP proxy integration capturing agent inputs, tool descriptions, MCP server responses. Critical for detecting MCP tool poisoning.
- **Cloud Collector**: SaaS AI platform connectors for sanctioned cloud AI service interactions.
- **OpenTelemetry Collector**: Standardised telemetry for custom AI pipelines.

## Policy Engine
Three enforcement modes:
- **Log**: Record interaction without intervention. Used for initial deployment and baselining.
- **Redact**: Detect and replace sensitive content before submission or delivery. Supports replacement, masking, partial masking, hash, and format-preserving encryption.
- **Block**: Prevent the request from reaching the AI model or user. Applied to confirmed threats.

Two rule types:
- **Access Rules**: Attribute-based conditions on user identity, device, application ID.
- **Prompt Rules**: Content-based detectors inspecting prompts and responses.

## DLP Capabilities
- Detects PII, credentials, API keys, regulated data before AI model exposure
- Identifies code in 26 programming languages to prevent IP leakage
- 300,000+ adversarial prompts in detection library
- 180+ attack techniques tracked
- 99% detection efficacy at sub-30ms latency (vendor claimed)

## SIEM Integration
AIDR streams findings to CrowdStrike Falcon Next-Gen SIEM. For Splunk: uses HEC and Syslog to forward structured telemetry to idx_ai_crowdstrike index.

## LiteLLM Integration
Configure the crowdstrike_aidr guardrail in LiteLLM config.yaml. Set CS_AIDR_TOKEN and CS_AIDR_BASE_URL environment variables. Use default_on: true for always-on protection or toggle per model.

## Console Access
Falcon console → Open menu → AI detection and response → Visibility. Roles: AIDR Admin (full configuration), AIDR Analyst (view and logs).

## Network Requirements
AIDR collectors communicate over port 443 using FQDNs. Add AIDR FQDNs to network allowlists before deployment.
