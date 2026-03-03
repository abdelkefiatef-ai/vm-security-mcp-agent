# VM Security MCP Agent

Open-source LLM-based MCP agent that analyzes VM misconfigurations and generates Top-5 cyber risks per VM. Uses **Ollama** for local LLM inference with Llama, Mistral, or Mixtral models.

## Features

- **18 Detection Rules** based on CIS Benchmarks and NIST controls
- **Pure LLM Analysis** - No rule-based fallback, fully AI-powered risk assessment
- **Top-5 Cyber Risks** per VM with CVSS scores, attack vectors, and remediation
- **MCP Server** for AI agent integration
- **REST API** for programmatic access
- **React Dashboard** for visual analysis

## Prerequisites

1. **Node.js 18+** and **npm/bun**
2. **Ollama** for local LLM inference

## Installation

### 1. Install Ollama

```bash
# Linux/macOS
curl -fsSL https://ollama.com/install.sh | sh

# Or download from https://ollama.com
```

### 2. Start Ollama and Pull Model

```bash
# Start the server
ollama serve

# In another terminal, pull a model
ollama pull llama3.2

# Alternative models (choose based on your RAM):
# ollama pull llama3.1  (16GB RAM)
# ollama pull mistral   (8GB RAM)
# ollama pull mixtral   (24GB RAM)
```

### 3. Set Up the Project

```bash
# Create a new Next.js project
npx create-next-app@latest vm-security-agent --typescript --tailwind --app

# Or with bun
bun create next-app vm-security-agent --typescript --tailwind --app

cd vm-security-agent

# Install dependencies
npm install lucide-react class-variance-authority clsx tailwind-merge
npm install @radix-ui/react-alert-dialog @radix-ui/react-select @radix-ui/react-scroll-area @radix-ui/react-separator @radix-ui/react-tabs @radix-ui/react-progress
```

### 4. Copy Source Files

Copy the files from this package to your project:

```
ollama-client.ts      → src/lib/ollama-client.ts
types.ts              → src/lib/vm-security/types.ts
detection-rules.ts    → src/lib/vm-security/detection-rules.ts
risk-engine.ts        → src/lib/vm-security/risk-engine.ts
sample-data.ts        → src/lib/vm-security/sample-data.ts
server.ts             → src/mcp/server.ts
api-route.ts          → src/app/api/vm-security/route.ts
dashboard.tsx         → src/app/page.tsx
```

### 5. Add UI Components

Create these components in `src/components/ui/`:

```bash
npx shadcn-ui@latest add card button badge tabs progress alert alert-dialog select scroll-area separator
```

### 6. Run the Application

```bash
npm run dev
# or
bun run dev
```

Open http://localhost:3000 in your browser.

## Project Structure

```
src/
├── app/
│   ├── api/vm-security/
│   │   └── route.ts          # REST API endpoints
│   └── page.tsx              # React dashboard
├── components/ui/            # shadcn/ui components
├── lib/
│   ├── ollama-client.ts      # Ollama API client
│   └── vm-security/
│       ├── types.ts          # TypeScript types
│       ├── detection-rules.ts # 18 security rules
│       ├── risk-engine.ts    # LLM risk analysis
│       └── sample-data.ts    # Sample VM data
└── mcp/
    └── server.ts             # MCP server implementation
```

## API Endpoints

### GET Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/vm-security?action=list` | List all VMs |
| `GET /api/vm-security?action=get&vmId=xxx` | Get VM details |
| `GET /api/vm-security?action=scan&vmId=xxx` | Scan VM for misconfigurations |
| `GET /api/vm-security?action=rules` | Get detection rules |
| `GET /api/vm-security?action=llm-status` | Check Ollama status |
| `GET /api/vm-security?action=summary` | Get summary report |

### POST Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/vm-security` with `{action: "analyze", vmId: "xxx"}` | Generate Top-5 risks |
| `POST /api/vm-security` with `{action: "report", vmId: "xxx"}` | Full security report |
| `POST /api/vm-security` with `{action: "batch", vmIds: [...]}` | Batch analysis |

## Detection Rules

The agent includes 18 detection rules across 5 categories:

### Network Security (NS)
- NS-001: Open Security Group (0.0.0.0/0)
- NS-002: SSH Open to Internet
- NS-003: RDP Open to Internet
- NS-004: Default Security Group In Use

### Identity & Access (IA)
- IA-001: Missing IAM Role
- IA-003: Overly Permissive IAM Role
- IA-004: IMDSv1 Enabled (SSRF Vulnerability)

### Data Protection (DP)
- DP-001: Unencrypted Boot Disk
- DP-002: Unencrypted Data Disks
- DP-003: Sensitive Data in User Data

### Monitoring & Logging (ML)
- ML-001: Detailed Monitoring Disabled
- ML-002: VPC Flow Logs Disabled
- ML-003: CloudTrail/Activity Logs Disabled

### Compute Security (CS)
- CS-001: No Backup Configured
- CS-002: Deprecated Instance Type
- CS-003: Missing Required Tags
- CS-004: Public IP Assigned

## MCP Tools

The MCP server exposes 7 tools:

1. `scan_vm` - Scan VM for misconfigurations
2. `analyze_risks` - Generate Top-5 cyber risks
3. `generate_report` - Full security report
4. `list_vms` - List available VMs
5. `get_vm` - Get VM details
6. `batch_analyze` - Analyze multiple VMs
7. `get_detection_rules` - Get rule definitions

## Environment Variables

```bash
# Optional: Custom Ollama endpoint
OLLAMA_BASE_URL=http://localhost:11434

# Optional: Default model
OLLAMA_MODEL=llama3.2
```

## Model Recommendations

| Model | RAM Required | Description |
|-------|-------------|-------------|
| llama3.2 | 8GB | Recommended - Latest Llama, excellent reasoning |
| llama3.1 | 16GB | Powerful for complex analysis |
| mistral | 8GB | Fast and efficient |
| mixtral | 24GB | MoE model, best analysis quality |

## License

MIT License - Open Source
