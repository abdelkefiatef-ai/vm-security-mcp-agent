/**
 * API Route: VM Security Analysis
 * Provides REST API endpoints for the MCP VM Security Agent
 */

import { NextRequest, NextResponse } from 'next/server';
import { RiskAnalysisEngine } from '@/lib/vm-security/risk-engine';
import { scanVMForMisconfigurations, getRuleCount, getRulesByCategory, getRulesBySeverity } from '@/lib/vm-security/detection-rules';
import { sampleVMs, getVMById, generateRandomVMs } from '@/lib/vm-security/sample-data';
import type { VMInstance } from '@/lib/vm-security/types';

// Initialize risk analysis engine
const riskEngine = new RiskAnalysisEngine();

// ============================================================================
// API Handlers
// ============================================================================

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action') || 'list';
  
  try {
    switch (action) {
      case 'list':
        return handleListVMs(searchParams);
      
      case 'get':
        return handleGetVM(searchParams);
      
      case 'scan':
        return handleScanVM(searchParams);
      
      case 'rules':
        return handleGetRules();
      
      case 'llm-status':
        return handleLLMStatus();
      
      case 'summary':
        return handleSummary();
      
      default:
        return NextResponse.json(
          { error: 'Invalid action. Use: list, get, scan, rules, llm-status, summary' },
          { status: 400 }
        );
    }
  } catch (error) {
    console.error('API Error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, ...params } = body;
    
    switch (action) {
      case 'analyze':
        return handleAnalyzeRisks(params);
      
      case 'report':
        return handleGenerateReport(params);
      
      case 'batch':
        return handleBatchAnalyze(params);
      
      case 'generate-vms':
        return handleGenerateVMs(params);
      
      case 'custom-scan':
        return handleCustomScan(params);
      
      default:
        return NextResponse.json(
          { error: 'Invalid action. Use: analyze, report, batch, generate-vms, custom-scan' },
          { status: 400 }
        );
    }
  } catch (error) {
    console.error('API Error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    );
  }
}

// ============================================================================
// GET Handlers
// ============================================================================

async function handleListVMs(searchParams: URLSearchParams) {
  const provider = searchParams.get('provider');
  const region = searchParams.get('region');
  
  let vms = [...sampleVMs];
  
  if (provider) {
    vms = vms.filter(vm => vm.provider === provider);
  }
  if (region) {
    vms = vms.filter(vm => vm.region === region);
  }
  
  const vmList = vms.map(vm => ({
    id: vm.id,
    name: vm.name,
    provider: vm.provider,
    region: vm.region,
    state: vm.state,
    instanceType: vm.instanceType,
    hasPublicIP: vm.networkInterfaces.some(ni => ni.publicIpAssigned),
    diskCount: vm.disks.length,
    encryptedDisks: vm.disks.filter(d => d.encrypted).length,
  }));
  
  return NextResponse.json({
    success: true,
    total: vmList.length,
    virtualMachines: vmList,
  });
}

async function handleGetVM(searchParams: URLSearchParams) {
  const vmId = searchParams.get('vmId');
  
  if (!vmId) {
    return NextResponse.json(
      { error: 'vmId parameter is required' },
      { status: 400 }
    );
  }
  
  const vm = getVMById(vmId);
  
  if (!vm) {
    return NextResponse.json(
      { error: `VM not found: ${vmId}` },
      { status: 404 }
    );
  }
  
  return NextResponse.json({
    success: true,
    virtualMachine: vm,
  });
}

async function handleScanVM(searchParams: URLSearchParams) {
  const vmId = searchParams.get('vmId');
  
  if (!vmId) {
    return NextResponse.json(
      { error: 'vmId parameter is required' },
      { status: 400 }
    );
  }
  
  const vm = getVMById(vmId);
  
  if (!vm) {
    return NextResponse.json(
      { error: `VM not found: ${vmId}` },
      { status: 404 }
    );
  }
  
  const misconfigurations = scanVMForMisconfigurations(vm);
  const rulesApplied = getRuleCount();
  
  return NextResponse.json({
    success: true,
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
  });
}

async function handleGetRules() {
  return NextResponse.json({
    success: true,
    totalRules: getRuleCount(),
    rules: {
      network_security: getRulesByCategory('network_security').map(r => ({
        id: r.id,
        name: r.name,
        severity: r.severity,
        description: r.description,
      })),
      identity_access: getRulesByCategory('identity_access').map(r => ({
        id: r.id,
        name: r.name,
        severity: r.severity,
        description: r.description,
      })),
      data_protection: getRulesByCategory('data_protection').map(r => ({
        id: r.id,
        name: r.name,
        severity: r.severity,
        description: r.description,
      })),
      monitoring_logging: getRulesByCategory('monitoring_logging').map(r => ({
        id: r.id,
        name: r.name,
        severity: r.severity,
        description: r.description,
      })),
      compute_security: getRulesByCategory('compute_security').map(r => ({
        id: r.id,
        name: r.name,
        severity: r.severity,
        description: r.description,
      })),
    },
    severityBreakdown: {
      critical: getRulesBySeverity('critical').length,
      high: getRulesBySeverity('high').length,
      medium: getRulesBySeverity('medium').length,
      low: getRulesBySeverity('low').length,
    },
  });
}

async function handleLLMStatus() {
  const isRunning = await riskEngine.isServerAvailable();
  const availableModels = isRunning ? await riskEngine.getAvailableModels() : [];
  
  return NextResponse.json({
    success: true,
    llmServer: 'Ollama',
    status: isRunning ? 'running' : 'not_running',
    endpoint: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
    availableModels,
    recommendedModels: [
      { name: 'llama3.2', description: 'Latest Llama, 8GB RAM', recommended: true },
      { name: 'llama3.1', description: 'Powerful analysis, 16GB RAM', recommended: true },
      { name: 'mistral', description: 'Fast and efficient, 8GB RAM', recommended: true },
      { name: 'mixtral', description: 'MoE model, 24GB RAM', recommended: false },
    ],
    message: isRunning 
      ? 'LLM server is available for AI-powered risk analysis'
      : 'Start Ollama: ollama serve && ollama pull llama3.2',
  });
}

async function handleSummary() {
  const allScans = sampleVMs.map(vm => {
    const misconfigurations = scanVMForMisconfigurations(vm);
    return {
      vmId: vm.id,
      vmName: vm.name,
      provider: vm.provider,
      misconfigurationCount: misconfigurations.length,
      critical: misconfigurations.filter(m => m.severity === 'critical').length,
      high: misconfigurations.filter(m => m.severity === 'high').length,
    };
  });
  
  const totalMisco = allScans.reduce((sum, s) => sum + s.misconfigurationCount, 0);
  const totalCritical = allScans.reduce((sum, s) => sum + s.critical, 0);
  const totalHigh = allScans.reduce((sum, s) => sum + s.high, 0);
  
  return NextResponse.json({
    success: true,
    totalVMs: sampleVMs.length,
    totalMisconfigurations: totalMisco,
    criticalIssues: totalCritical,
    highIssues: totalHigh,
    detectionRules: getRuleCount(),
    vmScans: allScans,
  });
}

// ============================================================================
// POST Handlers
// ============================================================================

async function handleAnalyzeRisks(params: { vmId: string; model?: string }) {
  const { vmId, model = 'llama3.2' } = params;
  
  if (!vmId) {
    return NextResponse.json(
      { error: 'vmId is required' },
      { status: 400 }
    );
  }
  
  const vm = getVMById(vmId);
  
  if (!vm) {
    return NextResponse.json(
      { error: `VM not found: ${vmId}` },
      { status: 404 }
    );
  }
  
  riskEngine.setModel(model);
  const misconfigurations = scanVMForMisconfigurations(vm);
  const top5Risks = await riskEngine.generateTop5Risks(vm, misconfigurations);
  
  return NextResponse.json({
    success: true,
    vmId: vm.id,
    vmName: vm.name,
    provider: vm.provider,
    analysisTimestamp: new Date().toISOString(),
    modelUsed: model,
    misconfigurationCount: misconfigurations.length,
    top5Risks,
  });
}

async function handleGenerateReport(params: { vmId: string; model?: string }) {
  const { vmId, model = 'llama3.2' } = params;
  
  if (!vmId) {
    return NextResponse.json(
      { error: 'vmId is required' },
      { status: 400 }
    );
  }
  
  const vm = getVMById(vmId);
  
  if (!vm) {
    return NextResponse.json(
      { error: `VM not found: ${vmId}` },
      { status: 404 }
    );
  }
  
  riskEngine.setModel(model);
  const misconfigurations = scanVMForMisconfigurations(vm);
  const report = await riskEngine.generateSecurityReport(vm, misconfigurations, getRuleCount());
  
  return NextResponse.json({
    success: true,
    report,
  });
}

async function handleBatchAnalyze(params: { vmIds: string[]; model?: string }) {
  const { vmIds, model = 'llama3.2' } = params;
  
  if (!vmIds || !Array.isArray(vmIds) || vmIds.length === 0) {
    return NextResponse.json(
      { error: 'vmIds array is required' },
      { status: 400 }
    );
  }
  
  riskEngine.setModel(model);
  const results: Array<{
    vmId: string;
    vmName: string;
    riskScore: number;
    riskLevel: string;
    misconfigurationCount: number;
    criticalCount: number;
    highCount: number;
  }> = [];
  
  for (const vmId of vmIds) {
    const vm = getVMById(vmId);
    if (vm) {
      const misconfigurations = scanVMForMisconfigurations(vm);
      const report = await riskEngine.generateSecurityReport(vm, misconfigurations);
      
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
  
  const avgRiskScore = results.length > 0
    ? Math.round(results.reduce((sum, r) => sum + r.riskScore, 0) / results.length)
    : 0;
  
  return NextResponse.json({
    success: true,
    batchAnalysisTimestamp: new Date().toISOString(),
    modelUsed: model,
    vmsAnalyzed: results.length,
    averageRiskScore: avgRiskScore,
    criticalVMs: results.filter(r => r.riskLevel === 'critical').length,
    highRiskVMs: results.filter(r => r.riskLevel === 'high').length,
    mediumRiskVMs: results.filter(r => r.riskLevel === 'medium').length,
    lowRiskVMs: results.filter(r => r.riskLevel === 'low').length,
    secureVMs: results.filter(r => r.riskLevel === 'secure').length,
    results,
  });
}

async function handleGenerateVMs(params: { count: number; provider?: string }) {
  const { count = 5, provider = 'aws' } = params;
  
  const vms = generateRandomVMs(Math.min(count, 20), provider as 'aws' | 'azure' | 'gcp');
  
  return NextResponse.json({
    success: true,
    generated: vms.length,
    provider,
    virtualMachines: vms.map(vm => ({
      id: vm.id,
      name: vm.name,
      region: vm.region,
      instanceType: vm.instanceType,
    })),
  });
}

async function handleCustomScan(params: { vmConfig: VMInstance }) {
  const { vmConfig } = params;
  
  if (!vmConfig) {
    return NextResponse.json(
      { error: 'vmConfig is required' },
      { status: 400 }
    );
  }
  
  const misconfigurations = scanVMForMisconfigurations(vmConfig);
  
  return NextResponse.json({
    success: true,
    vmId: vmConfig.id,
    vmName: vmConfig.name,
    scanTimestamp: new Date().toISOString(),
    totalMisconfigurations: misconfigurations.length,
    severityBreakdown: {
      critical: misconfigurations.filter(m => m.severity === 'critical').length,
      high: misconfigurations.filter(m => m.severity === 'high').length,
      medium: misconfigurations.filter(m => m.severity === 'medium').length,
      low: misconfigurations.filter(m => m.severity === 'low').length,
    },
    misconfigurations,
  });
}
