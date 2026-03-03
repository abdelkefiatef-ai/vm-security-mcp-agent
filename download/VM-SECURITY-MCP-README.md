# VM Security MCP Agent

## Overview

An open-source LLM-based MCP (Model Context Protocol) agent that analyzes VM misconfigurations and generates Top-5 cyber risk reports using **local Llama LLM** via Ollama.

## Features

### 🔍 VM Misconfiguration Detection
- **18 Detection Rules** based on CIS Benchmarks and NIST Controls
- Categories: Network Security, Identity & Access, Data Protection, Monitoring, Compute Security
- Severity levels: Critical, High, Medium, Low

### 🧠 AI-Powered Risk Analysis
- Uses **Llama 3.2/3.1** running locally via Ollama
- Generates **Top-5 Cyber Risks** per VM
- Includes CVSS scores, attack vectors, business impact
- Provides remediation steps with estimated time

### 🔧 MCP Tools Available
1. `list_vms` - List available VMs for analysis
2. `get_vm` - Get detailed VM configuration
3. `scan_vm` - Scan for misconfigurations
4. `analyze_risks` - AI-powered risk analysis
5. `generate_report` - Complete security report
6. `check_llm_status` - Check Ollama availability
7. `batch_analyze` - Analyze multiple VMs at once

## Quick Start

### 1. Install Ollama
```bash
# macOS/Linux
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve
```

### 2. Pull Llama Model
```bash
ollama pull llama3.2
```

### 3. Start the Application
```bash
bun run dev
```

### 4. Access the Dashboard
Open http://localhost:3000

## API Endpoints

### GET Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/vm-security?action=list` | List all VMs |
| `/api/vm-security?action=get&vmId=xxx` | Get VM details |
| `/api/vm-security?action=scan&vmId=xxx` | Scan for misconfigurations |
| `/api/vm-security?action=rules` | Get all detection rules |
| `/api/vm-security?action=llm-status` | Check LLM status |
| `/api/vm-security?action=summary` | Get overall summary |

### POST Endpoints

```javascript
// Analyze risks
fetch('/api/vm-security', {
  method: 'POST',
  body: JSON.stringify({
    action: 'analyze',
    vmId: 'i-xxx',
    model: 'llama3.2'
  })
});

// Generate full report
fetch('/api/vm-security', {
  method: 'POST',
  body: JSON.stringify({
    action: 'report',
    vmId: 'i-xxx',
    model: 'llama3.2'
  })
});

// Batch analyze
fetch('/api/vm-security', {
  method: 'POST',
  body: JSON.stringify({
    action: 'batch',
    vmIds: ['i-xxx', 'i-yyy'],
    model: 'llama3.2'
  })
});
```

## Detection Rules Summary

| ID | Category | Severity | Description |
|----|----------|----------|-------------|
| NS-001 | Network Security | Critical | SSH Port Open to Internet |
| NS-002 | Network Security | Critical | RDP Port Open to Internet |
| NS-003 | Network Security | High | Public IP Assigned |
| NS-004 | Network Security | Medium | Default Security Group |
| NS-005 | Network Security | Critical | All Ports Open |
| IA-001 | Identity Access | High | No IAM Role Attached |
| IA-002 | Identity Access | Critical | Overly Permissive IAM |
| IA-003 | Identity Access | Critical | IMDSv1 Enabled (SSRF) |
| DP-001 | Data Protection | High | Unencrypted Boot Disk |
| DP-002 | Data Protection | High | Unencrypted Data Disk |
| DP-003 | Data Protection | Critical | Sensitive Data in User Data |
| ML-001 | Monitoring | Medium | Detailed Monitoring Disabled |
| ML-002 | Monitoring | High | VPC Flow Logs Disabled |
| ML-003 | Monitoring | High | CloudTrail Disabled |
| CS-001 | Compute Security | High | Backup Not Configured |
| CS-002 | Compute Security | Medium | Secure Boot Disabled |
| CS-003 | Compute Security | Low | Missing Required Tags |
| CS-004 | Compute Security | Medium | Disk Not Deleted on Termination |

## Supported Models

| Model | RAM Required | Recommended |
|-------|-------------|-------------|
| llama3.2 | 8GB | ✅ Yes |
| llama3.1 | 16GB | ✅ Yes |
| mistral | 8GB | ✅ Yes |
| mixtral | 24GB | Advanced |

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web Dashboard │────▶│   REST API      │────▶│   Risk Engine   │
│   (React/Next)  │     │   (Next.js)     │     │   (Ollama LLM)  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │ Detection Rules │
                        │ (18 CIS/NIST)   │
                        └─────────────────┘
```

## MCP Server Usage

```typescript
import { VMSecurityMCPServer } from './mcp/server';

// Start MCP server
const server = new VMSecurityMCPServer();
await server.run();
```

## Environment Variables

```bash
OLLAMA_BASE_URL=http://localhost:11434  # Ollama server URL
OLLAMA_MODEL=llama3.2                    # Default model
```

## License

MIT License - Open Source
