/**
 * MCP Server Implementation for VM Security Analysis Agent
 * Provides tools for analyzing VM misconfigurations and generating cyber risk reports
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { RiskAnalysisEngine } from '../lib/vm-security/risk-engine';
import { scanVMForMisconfigurations, getRuleCount } from '../lib/vm-security/detection-rules';
import { sampleVMs, getVMById } from '../lib/vm-security/sample-data';
import type { VMInstance, VMSecurityReport, CyberRisk, Misconfiguration } from '../lib/vm-security/types';

// ============================================================================
// MCP Server Configuration
// ============================================================================

const SERVER_NAME = 'vm-security-analyzer';
const SERVER_VERSION = '1.0.0';

// ============================================================================
// Tool Definitions
// ============================================================================

const TOOLS = [
  {
    name: 'list_vms',
    description: 'List all available virtual machines for security analysis. Returns a summary of each VM including ID, name, provider, region, and state.',
    inputSchema: {
      type: 'object',
      properties: {
        provider: {
          type: 'string',
          enum: ['aws', 'azure', 'gcp', 'on-premise'],
          description: 'Filter by cloud provider (optional)',
        },
        region: {
          type: 'string',
          description: 'Filter by region (optional)',
        },
      },
    },
  },
  {
    name: 'get_vm',
    description: 'Get detailed configuration of a specific VM by its ID. Returns complete VM configuration including network, storage, identity, and security settings.',
    inputSchema: {
      type: 'object',
      properties: {
        vmId: {
          type: 'string',
          description: 'The VM ID (e.g., i-0abc123def456)',
        },
      },
      required: ['vmId'],
    },
  },
  {
    name: 'scan_vm',
    description: 'Scan a VM for security misconfigurations. Applies all detection rules and returns a list of identified misconfigurations with severity levels and remediation guidance.',
    inputSchema: {
      type: 'object',
      properties: {
        vmId: {
          type: 'string',
          description: 'The VM ID to scan',
        },
      },
      required: ['vmId'],
    },
  },
  {
    name: 'analyze_risks',
    description: 'Perform AI-powered risk analysis on a VM using local Llama LLM. Generates Top-5 cyber risks with detailed attack vectors, business impact, and remediation steps.',
    inputSchema: {
      type: 'object',
      properties: {
        vmId: {
          type: 'string',
          description: 'The VM ID to analyze',
        },
        model: {
          type: 'string',
          description: 'LLM model to use (default: llama3.2)',
          default: 'llama3.2',
        },
      },
      required: ['vmId'],
    },
  },
  {
    name: 'generate_report',
    description: 'Generate a comprehensive security report for a VM. Includes misconfigurations, Top-5 cyber risks, compliance score, and recommendations. Uses local LLM for risk analysis.',
    inputSchema: {
      type: 'object',
      properties: {
        vmId: {
          type: 'string',
          description: 'The VM ID to generate report for',
        },
        model: {
          type: 'string',
          description: 'LLM model to use (default: llama3.2)',
          default: 'llama3.2',
        },
      },
      required: ['vmId'],
    },
  },
  {
    name: 'check_llm_status',
    description: 'Check if the local LLM (Ollama) is running and available. Returns available models and server status.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'batch_analyze',
    description: 'Analyze multiple VMs at once and generate summary report. Useful for infrastructure-wide security assessment.',
    inputSchema: {
      type: 'object',
      properties: {
        vmIds: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of VM IDs to analyze',
        },
      },
      required: ['vmIds'],
    },
  },
];

// ============================================================================
// Server Implementation
// ============================================================================

export class VMSecurityMCPServer {
  private server: Server;
  private riskEngine: RiskAnalysisEngine;

  constructor() {
    this.server = new Server(
      { name: SERVER_NAME, version: SERVER_VERSION },
      { capabilities: { tools: {} } }
    );
    this.riskEngine = new RiskAnalysisEngine();
    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: TOOLS };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'list_vms':
            return await this.handleListVMs(args as { provider?: string; region?: string });
          
          case 'get_vm':
            return await this.handleGetVM(args as { vmId: string });
          
          case 'scan_vm':
            return await this.handleScanVM(args as { vmId: string });
          
          case 'analyze_risks':
            return await this.handleAnalyzeRisks(args as { vmId: string; model?: string });
          
          case 'generate_report':
            return await this.handleGenerateReport(args as { vmId: string; model?: string });
          
          case 'check_llm_status':
            return await this.handleCheckLLMStatus();
          
          case 'batch_analyze':
            return await this.handleBatchAnalyze(args as { vmIds: string[] });
          
          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (error) {
        if (error instanceof McpError) {
          throw error;
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Error executing ${name}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    });
  }

  // ============================================================================
  // Tool Handlers
  // ============================================================================

  private async handleListVMs(args: { provider?: string; region?: string }) {
    let vms = [...sampleVMs];

    if (args.provider) {
      vms = vms.filter(vm => vm.provider === args.provider);
    }
    if (args.region) {
      vms = vms.filter(vm => vm.region === args.region);
    }

    const vmList = vms.map(vm => ({
      id: vm.id,
      name: vm.name,
      provider: vm.provider,
      region: vm.region,
      state: vm.state,
      instanceType: vm.instanceType,
      hasPublicIP: vm.networkInterfaces.some(ni => ni.publicIpAssigned),
    }));

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            total: vmList.length,
            virtualMachines: vmList,
          }, null, 2),
        },
      ],
    };
  }

  private async handleGetVM(args: { vmId: string }) {
    const vm = getVMById(args.vmId);
    
    if (!vm) {
      throw new McpError(ErrorCode.InvalidParams, `VM not found: ${args.vmId}`);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(vm, null, 2),
        },
      ],
    };
  }

  private async handleScanVM(args: { vmId: string }) {
    const vm = getVMById(args.vmId);
    
    if (!vm) {
      throw new McpError(ErrorCode.InvalidParams, `VM not found: ${args.vmId}`);
    }

    const misconfigurations = scanVMForMisconfigurations(vm);
    const rulesApplied = getRuleCount();

    const summary = {
      vmId: vm.id,
      vmName: vm.name,
      scanTimestamp: new Date().toISOString(),
      rulesApplied,
      totalMisconfigurations: misconfigurations.length,
      severityBreakdown: {
        critical: misconfigurations.filter(m => m.severity === 'critical').length,
        high: misconfigurations.filter(m => m.severity === 'high').length,
        medium: misconfigurations.filter(m => m.severity === 'medium').length,
        low: misconfigurations.filter(m => m.severity === 'low').length,
      },
      misconfigurations,
    };

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(summary, null, 2),
        },
      ],
    };
  }

  private async handleAnalyzeRisks(args: { vmId: string; model?: string }) {
    const vm = getVMById(args.vmId);
    
    if (!vm) {
      throw new McpError(ErrorCode.InvalidParams, `VM not found: ${args.vmId}`);
    }

    // Set model if specified
    if (args.model) {
      this.riskEngine.setModel(args.model);
    }

    const misconfigurations = scanVMForMisconfigurations(vm);
    const top5Risks = await this.riskEngine.generateTop5Risks(vm, misconfigurations);

    const result = {
      vmId: vm.id,
      vmName: vm.name,
      provider: vm.provider,
      analysisTimestamp: new Date().toISOString(),
      modelUsed: args.model || 'llama3.2',
      misconfigurationCount: misconfigurations.length,
      top5Risks,
    };

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }

  private async handleGenerateReport(args: { vmId: string; model?: string }) {
    const vm = getVMById(args.vmId);
    
    if (!vm) {
      throw new McpError(ErrorCode.InvalidParams, `VM not found: ${args.vmId}`);
    }

    // Set model if specified
    if (args.model) {
      this.riskEngine.setModel(args.model);
    }

    const misconfigurations = scanVMForMisconfigurations(vm);
    const rulesApplied = getRuleCount();
    const report = await this.riskEngine.generateSecurityReport(vm, misconfigurations, rulesApplied);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(report, null, 2),
        },
      ],
    };
  }

  private async handleCheckLLMStatus() {
    const isRunning = await this.riskEngine.isServerAvailable();
    const availableModels = isRunning ? await this.riskEngine.getAvailableModels() : [];

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            llmServer: 'Ollama',
            status: isRunning ? 'running' : 'not_running',
            endpoint: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
            availableModels,
            recommendedModels: ['llama3.2', 'llama3.1', 'mistral', 'mixtral'],
            message: isRunning 
              ? 'LLM server is available for risk analysis'
              : 'LLM server is not running. Start Ollama with: ollama serve && ollama pull llama3.2',
          }, null, 2),
        },
      ],
    };
  }

  private async handleBatchAnalyze(args: { vmIds: string[] }) {
    const results: Array<{
      vmId: string;
      vmName: string;
      riskScore: number;
      riskLevel: string;
      misconfigurationCount: number;
      criticalCount: number;
      highCount: number;
    }> = [];

    for (const vmId of args.vmIds) {
      const vm = getVMById(vmId);
      if (vm) {
        const misconfigurations = scanVMForMisconfigurations(vm);
        const report = await this.riskEngine.generateSecurityReport(vm, misconfigurations);
        
        results.push({
          vmId: vm.id,
          vmName: vm.name,
          riskScore: report.overallRiskScore,
          riskLevel: report.riskLevel,
          misconfigurationCount: misconfigurations.length,
          criticalCount: misconfigurations.filter(m => m.severity === 'critical').length,
          highCount: misconfigurations.filter(m => m.severity === 'high').length,
        });
      }
    }

    // Calculate summary statistics
    const avgRiskScore = results.length > 0
      ? Math.round(results.reduce((sum, r) => sum + r.riskScore, 0) / results.length)
      : 0;

    const summary = {
      batchAnalysisTimestamp: new Date().toISOString(),
      vmsAnalyzed: results.length,
      averageRiskScore: avgRiskScore,
      criticalVMs: results.filter(r => r.riskLevel === 'critical').length,
      highRiskVMs: results.filter(r => r.riskLevel === 'high').length,
      mediumRiskVMs: results.filter(r => r.riskLevel === 'medium').length,
      lowRiskVMs: results.filter(r => r.riskLevel === 'low').length,
      secureVMs: results.filter(r => r.riskLevel === 'secure').length,
      results,
    };

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(summary, null, 2),
        },
      ],
    };
  }

  // ============================================================================
  // Server Start
  // ============================================================================

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error(`VM Security MCP Server running on stdio`);
  }
}

// ============================================================================
// Export for CLI and API usage
// ============================================================================

export async function runMCPServer() {
  const server = new VMSecurityMCPServer();
  await server.run();
}

// Run if called directly
if (process.argv[1]?.includes('mcp-server')) {
  runMCPServer().catch(console.error);
}
