/**
 * Pure LLM-Based Risk Analysis Engine
 * Uses Groq's FREE Llama API
 * Version: 3.0 - Clean Implementation
 */

import {
  VMInstance,
  Misconfiguration,
  CyberRisk,
  VMSecurityReport,
  RiskCategory,
  Severity
} from './types';

// ============================================================================
// Groq API Configuration
// ============================================================================

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL = 'llama-3.3-70b-versatile';

// ============================================================================
// Risk Analysis Engine Class
// ============================================================================

export class RiskAnalysisEngine {
  private modelName: string;

  constructor(modelName: string = DEFAULT_MODEL) {
    this.modelName = modelName;
  }

  /**
   * Call Groq API directly
   */
  private async callGroq(systemPrompt: string, userPrompt: string): Promise<string> {
    // Get API key at runtime (not at import time)
    const apiKey = process.env.GROQ_API_KEY;
    
    if (!apiKey) {
      throw new Error('GROQ_API_KEY environment variable is required. Get your FREE key at https://console.groq.com/');
    }

    const response = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: this.modelName,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.3,
        max_tokens: 4096,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Groq API error (${response.status}): ${errorText}`);
    }

    const data = await response.json();
    return data.choices?.[0]?.message?.content || '';
  }

  /**
   * Generate complete security report
   */
  async generateSecurityReport(
    vm: VMInstance,
    misconfigurations: Misconfiguration[],
    rulesApplied: number = 18
  ): Promise<VMSecurityReport> {
    const startTime = Date.now();
    const analysis = await this.analyzeWithLLM(vm, misconfigurations);

    return {
      vmId: vm.id,
      vmName: vm.name,
      provider: vm.provider,
      region: vm.region,
      scanTimestamp: new Date().toISOString(),
      overallRiskScore: analysis.overallRiskScore,
      riskLevel: analysis.riskLevel,
      misconfigurations,
      top5Risks: analysis.top5Risks,
      complianceScore: analysis.complianceScore,
      recommendations: analysis.recommendations,
      analysisMetadata: {
        modelUsed: this.modelName,
        analysisDuration: Date.now() - startTime,
        rulesApplied
      }
    };
  }

  /**
   * Generate Top-5 Risks
   */
  async generateTop5Risks(vm: VMInstance, misconfigurations: Misconfiguration[]): Promise<CyberRisk[]> {
    if (misconfigurations.length === 0) return [];
    const analysis = await this.analyzeWithLLM(vm, misconfigurations);
    return analysis.top5Risks;
  }

  /**
   * Core LLM Analysis
   */
  private async analyzeWithLLM(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<{
    overallRiskScore: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
    top5Risks: CyberRisk[];
    complianceScore: number;
    recommendations: string[];
  }> {
    const systemPrompt = this.buildSystemPrompt();
    const userPrompt = this.buildUserPrompt(vm, misconfigurations);

    const response = await this.callGroq(systemPrompt, userPrompt);
    return this.parseResponse(response);
  }

  /**
   * Build system prompt for security analysis
   */
  private buildSystemPrompt(): string {
    return `You are an expert cloud security analyst. Analyze VM misconfigurations and generate a security risk assessment.

Respond with ONLY valid JSON in this exact format:
{
  "overallRiskScore": <0-100, where 100 is most secure>,
  "riskLevel": "<critical|high|medium|low|secure>",
  "complianceScore": <0-100>,
  "top5Risks": [
    {
      "id": "RISK-001",
      "title": "<risk title>",
      "category": "<network_security|identity_access|data_protection|monitoring_logging|compliance|compute_security>",
      "severity": "<critical|high|medium|low>",
      "cvssScore": <0.0-10.0>,
      "likelihood": "<very_high|high|medium|low|very_low>",
      "impact": "<catastrophic|critical|major|moderate|minor>",
      "description": "<detailed description>",
      "affectedMisconfigurations": ["<rule IDs>"],
      "attackVector": "<how attackers exploit this>",
      "potentialImpact": "<technical impact>",
      "businessImpact": "<business impact>",
      "remediationPriority": "<immediate|high|medium|low>",
      "remediationSteps": ["<step 1>", "<step 2>"],
      "estimatedRemediationTime": "<time estimate>",
      "references": ["<URLs>"]
    }
  ],
  "recommendations": ["<recommendation 1>", "<recommendation 2>"]
}

Analyze based on CIS benchmarks, NIST framework, and real-world attack patterns.`;
  }

  /**
   * Build user prompt with VM details
   */
  private buildUserPrompt(vm: VMInstance, misconfigurations: Misconfiguration[]): string {
    const miscoList = misconfigurations.map((m, i) => 
      `${i + 1}. [${m.severity.toUpperCase()}] ${m.title}\n   Rule: ${m.ruleId}\n   Issue: ${m.description}\n   Current: ${m.currentValue}\n   Recommended: ${m.recommendedValue}`
    ).join('\n\n');

    return `Analyze this VM for security risks:

**VM Details:**
- Name: ${vm.name}
- Provider: ${vm.provider.toUpperCase()}
- Region: ${vm.region}
- Instance: ${vm.instanceType}
- Public IP: ${vm.networkInterfaces.some(ni => ni.publicIpAssigned) ? 'YES' : 'NO'}
- Encrypted Disks: ${vm.disks.filter(d => d.encrypted).length}/${vm.disks.length}
- IAM Role: ${vm.iamRole?.name || 'None'}
- IMDSv2: ${vm.metadataServiceV2 ? 'Enabled' : 'Disabled'}

**Misconfigurations Found (${misconfigurations.length}):**
${miscoList}

Generate a security assessment with top 5 risks.`;
  }

  /**
   * Parse LLM response
   */
  private parseResponse(response: string): {
    overallRiskScore: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
    top5Risks: CyberRisk[];
    complianceScore: number;
    recommendations: string[];
  } {
    // Extract JSON
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('Invalid response from LLM - no JSON found');
    }

    const parsed = JSON.parse(jsonMatch[0]);

    // Validate categories and severities
    const validCategories: RiskCategory[] = ['network_security', 'identity_access', 'data_protection', 'monitoring_logging', 'compliance', 'compute_security'];
    const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const validRiskLevels = ['critical', 'high', 'medium', 'low', 'secure'] as const;

    // Map and validate risks
    const top5Risks: CyberRisk[] = (parsed.top5Risks || []).slice(0, 5).map((risk: Record<string, unknown>, index: number): CyberRisk => ({
      rank: index + 1,
      id: String(risk.id || `RISK-${index + 1}`),
      title: String(risk.title || 'Security Risk'),
      category: validCategories.includes(risk.category as RiskCategory) ? risk.category as RiskCategory : 'compute_security',
      severity: validSeverities.includes(risk.severity as Severity) ? risk.severity as Severity : 'medium',
      cvssScore: Math.min(10, Math.max(0, Number(risk.cvssScore) || 5.0)),
      likelihood: ['very_high', 'high', 'medium', 'low', 'very_low'].includes(String(risk.likelihood)) ? risk.likelihood as CyberRisk['likelihood'] : 'medium',
      impact: ['catastrophic', 'critical', 'major', 'moderate', 'minor'].includes(String(risk.impact)) ? risk.impact as CyberRisk['impact'] : 'moderate',
      description: String(risk.description || 'Risk identified'),
      affectedMisconfigurations: Array.isArray(risk.affectedMisconfigurations) ? risk.affectedMisconfigurations as string[] : [],
      attackVector: String(risk.attackVector || 'Not specified'),
      potentialImpact: String(risk.potentialImpact || 'Not specified'),
      businessImpact: String(risk.businessImpact || 'Not specified'),
      remediationPriority: ['immediate', 'high', 'medium', 'low'].includes(String(risk.remediationPriority)) ? risk.remediationPriority as CyberRisk['remediationPriority'] : 'medium',
      remediationSteps: Array.isArray(risk.remediationSteps) ? risk.remediationSteps as string[] : ['Review and address'],
      estimatedRemediationTime: String(risk.estimatedRemediationTime || 'Unknown'),
      references: Array.isArray(risk.references) ? risk.references as string[] : []
    }));

    return {
      overallRiskScore: Math.min(100, Math.max(0, Number(parsed.overallRiskScore) || 50)),
      riskLevel: validRiskLevels.includes(parsed.riskLevel as typeof validRiskLevels[number]) ? parsed.riskLevel as typeof validRiskLevels[number] : 'medium',
      top5Risks,
      complianceScore: Math.min(100, Math.max(0, Number(parsed.complianceScore) || 50)),
      recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations.filter((r): r is string => typeof r === 'string') : ['Review security posture']
    };
  }

  /**
   * Check if API is configured
   */
  async isServerAvailable(): Promise<boolean> {
    return !!process.env.GROQ_API_KEY;
  }

  /**
   * Get available models
   */
  async getAvailableModels(): Promise<string[]> {
    return [
      'llama-3.3-70b-versatile',
      'llama-3.1-70b-versatile',
      'llama-3.1-8b-instant',
      'llama-3.2-3b-preview'
    ];
  }

  /**
   * Set model
   */
  setModel(modelName: string): void {
    this.modelName = modelName;
  }
}

// Export singleton
export const riskEngine = new RiskAnalysisEngine();
