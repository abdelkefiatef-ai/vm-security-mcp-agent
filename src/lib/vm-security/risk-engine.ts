/**
 * Pure LLM-Based Risk Analysis Engine
 * Uses Cloud LLM API for genuine AI-powered security analysis
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
// LLM API Client for Cloud Inference
// ============================================================================

interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface LLMResponse {
  choices: Array<{
    message: {
      content: string;
    };
  }>;
}

// ============================================================================
// Pure LLM Risk Analysis Engine
// ============================================================================

export class RiskAnalysisEngine {
  private modelName: string;
  private apiKey: string | undefined;
  private apiEndpoint: string;

  constructor(modelName: string = 'llama-3.3-70b') {
    this.modelName = modelName;
    // Get API key from environment variable (set in Vercel dashboard)
    this.apiKey = process.env.LLM_API_KEY || process.env.OPENAI_API_KEY;
    this.apiEndpoint = process.env.LLM_API_ENDPOINT || 'https://api.openai.com/v1/chat/completions';
  }

  /**
   * Call LLM API
   */
  private async callLLM(messages: LLMMessage[]): Promise<string> {
    // Try multiple LLM providers
    const providers = [
      { name: 'z-ai', fn: () => this.callZAI(messages) },
      { name: 'openai', fn: () => this.callOpenAI(messages) },
      { name: 'anthropic', fn: () => this.callAnthropic(messages) },
    ];

    for (const provider of providers) {
      try {
        const result = await provider.fn();
        if (result) {
          console.log(`[LLM] Successfully used ${provider.name}`);
          return result;
        }
      } catch (error) {
        console.log(`[LLM] ${provider.name} failed:`, error instanceof Error ? error.message : 'unknown error');
        continue;
      }
    }

    throw new Error('All LLM providers failed. Please set LLM_API_KEY or OPENAI_API_KEY environment variable in Vercel dashboard.');
  }

  /**
   * Call Z-AI SDK
   */
  private async callZAI(messages: LLMMessage[]): Promise<string | null> {
    try {
      const ZAI = (await import('z-ai-web-dev-sdk')).default;
      const zai = await ZAI.create();
      
      const completion = await zai.chat.completions.create({
        messages,
        temperature: 0.3,
        max_tokens: 4096
      });

      return completion.choices[0]?.message?.content || null;
    } catch {
      return null;
    }
  }

  /**
   * Call OpenAI-compatible API
   */
  private async callOpenAI(messages: LLMMessage[]): Promise<string | null> {
    if (!this.apiKey) return null;

    try {
      const response = await fetch(this.apiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: this.modelName,
          messages,
          temperature: 0.3,
          max_tokens: 4096
        })
      });

      if (!response.ok) return null;

      const data: LLMResponse = await response.json();
      return data.choices[0]?.message?.content || null;
    } catch {
      return null;
    }
  }

  /**
   * Call Anthropic API
   */
  private async callAnthropic(messages: LLMMessage[]): Promise<string | null> {
    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    if (!anthropicKey) return null;

    try {
      const systemMessage = messages.find(m => m.role === 'system')?.content || '';
      const userMessages = messages.filter(m => m.role !== 'system');

      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': anthropicKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          max_tokens: 4096,
          system: systemMessage,
          messages: userMessages.map(m => ({ role: m.role, content: m.content }))
        })
      });

      if (!response.ok) return null;

      const data = await response.json();
      return data.content?.[0]?.text || null;
    } catch {
      return null;
    }
  }

  /**
   * Generate complete security report using LLM
   */
  async generateSecurityReport(
    vm: VMInstance,
    misconfigurations: Misconfiguration[],
    rulesApplied: number = 18
  ): Promise<VMSecurityReport> {
    const startTime = Date.now();
    
    const analysis = await this.performLLMAnalysis(vm, misconfigurations);

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
   * Generate Top-5 Cyber Risks using LLM
   */
  async generateTop5Risks(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<CyberRisk[]> {
    if (misconfigurations.length === 0) {
      return [];
    }

    const analysis = await this.performLLMAnalysis(vm, misconfigurations);
    return analysis.top5Risks;
  }

  /**
   * Core LLM Analysis
   */
  private async performLLMAnalysis(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<{
    overallRiskScore: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
    top5Risks: CyberRisk[];
    complianceScore: number;
    recommendations: string[];
  }> {
    const systemPrompt = this.getSecurityAnalystPrompt();
    const userPrompt = this.buildAnalysisPrompt(vm, misconfigurations);

    const messages: LLMMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ];

    try {
      const response = await this.callLLM(messages);
      return this.parseLLMResponse(response, misconfigurations);
    } catch (error) {
      console.error('[RiskAnalysis] LLM analysis error:', error);
      throw error;
    }
  }

  /**
   * Security Analyst System Prompt
   */
  private getSecurityAnalystPrompt(): string {
    return `You are an elite cybersecurity analyst AI with deep expertise in cloud security, threat intelligence, and risk assessment.

Your task: Analyze VM misconfigurations and generate a comprehensive security risk report.

You MUST respond with ONLY valid JSON. No markdown, no code blocks, just pure JSON.

Response format:
{
  "overallRiskScore": <number 0-100, where 0=critical risk, 100=secure>,
  "riskLevel": "<critical|high|medium|low|secure>",
  "complianceScore": <number 0-100>,
  "top5Risks": [
    {
      "rank": <1-5>,
      "id": "RISK-001",
      "title": "<clear, actionable title describing the risk>",
      "category": "<network_security|identity_access|data_protection|monitoring_logging|compliance|compute_security>",
      "severity": "<critical|high|medium|low>",
      "cvssScore": <number 0.0-10.0>,
      "likelihood": "<very_high|high|medium|low|very_low>",
      "impact": "<catastrophic|critical|major|moderate|minor>",
      "description": "<detailed explanation of the risk>",
      "affectedMisconfigurations": ["<list of misconfiguration IDs>"],
      "attackVector": "<specific attack scenario how this could be exploited>",
      "potentialImpact": "<technical consequences>",
      "businessImpact": "<business and regulatory consequences>",
      "remediationPriority": "<immediate|high|medium|low>",
      "remediationSteps": ["<step 1>", "<step 2>", "<step 3>"],
      "estimatedRemediationTime": "<time estimate>",
      "references": ["<CIS benchmark or security reference>"]
    }
  ],
  "recommendations": [
    "<specific, actionable recommendation>",
    "<another recommendation>"
  ]
}

Guidelines:
- Base scores on real-world exploitability, not theoretical scenarios
- Consider attack chains where multiple misconfigurations combine
- Provide specific, actionable remediation steps
- Include realistic attack scenarios from threat intelligence
- Factor in business impact and regulatory compliance (GDPR, HIPAA, SOC2)`;
  }

  /**
   * Build analysis prompt for LLM
   */
  private buildAnalysisPrompt(vm: VMInstance, misconfigurations: Misconfiguration[]): string {
    return `## Security Analysis Request

Analyze this VM and its misconfigurations to generate a comprehensive security risk assessment.

### VM Details
- **Name:** ${vm.name}
- **ID:** ${vm.id}
- **Provider:** ${vm.provider.toUpperCase()}
- **Region:** ${vm.region}
- **Instance Type:** ${vm.instanceType}
- **State:** ${vm.state}

### Network Configuration
- **Public IP:** ${vm.networkInterfaces.some(ni => ni.publicIpAssigned) ? 'YES - Internet Accessible' : 'NO'}
- **Security Groups:** ${vm.securityGroups.map(sg => sg.name).join(', ')}

### Security Group Rules
${vm.securityGroups.map(sg => `
**${sg.name}** (${sg.isDefault ? 'DEFAULT' : 'Custom'}):
${sg.rules.map(r => `  - ${r.direction}: ${r.protocol} ports ${r.fromPort}-${r.toPort} from ${r.source}`).join('\n')}
`).join('\n')}

### Storage
- **Disks:** ${vm.disks.length}
- **Encrypted:** ${vm.disks.filter(d => d.encrypted).length}/${vm.disks.length}
- **Details:** ${vm.disks.map(d => `${d.name}(${d.encrypted ? 'encrypted' : 'UNENCRYPTED'})`).join(', ')}

### Identity & Access
- **IAM Role:** ${vm.iamRole ? vm.iamRole.name : 'NONE'}
- **IMDSv2:** ${vm.metadataServiceV2 ? 'Enabled (Secure)' : 'DISABLED (Vulnerable to SSRF)'}
- **Sensitive Data in User Data:** ${vm.userDataSensitiveData ? 'DETECTED' : 'None'}

### Monitoring
- **Detailed Monitoring:** ${vm.monitoring.detailedMonitoring ? 'Enabled' : 'Disabled'}
- **CloudTrail:** ${vm.monitoring.cloudTrailEnabled ? 'Enabled' : 'Disabled'}
- **VPC Flow Logs:** ${vm.monitoring.vpcFlowLogsEnabled ? 'Enabled' : 'Disabled'}

### Backup
- **Configured:** ${vm.backup.enabled ? 'Yes' : 'NO'}

### Detected Misconfigurations (${misconfigurations.length})
${misconfigurations.map((m, i) => `
**${i + 1}. ${m.title}** [${m.severity.toUpperCase()}]
- Rule: ${m.ruleId}
- Resource: ${m.affectedResource}
- Current: ${m.currentValue}
- Should Be: ${m.recommendedValue}
- Issue: ${m.description}
`).join('\n')}

---

Generate a comprehensive security analysis with exactly 5 prioritized risks. Consider attack chains and real-world exploitability.

Respond with ONLY the JSON object.`;
  }

  /**
   * Parse LLM response
   */
  private parseLLMResponse(
    response: string,
    misconfigurations: Misconfiguration[]
  ): {
    overallRiskScore: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
    top5Risks: CyberRisk[];
    complianceScore: number;
    recommendations: string[];
  } {
    try {
      // Extract JSON from response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('No JSON found in LLM response');
      }

      const parsed = JSON.parse(jsonMatch[0]);

      // Validate and sanitize
      const validCategories: RiskCategory[] = [
        'network_security', 'identity_access', 'data_protection',
        'monitoring_logging', 'compliance', 'compute_security'
      ];
      const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
      const validLikelihoods = ['very_high', 'high', 'medium', 'low', 'very_low'];
      const validImpacts = ['catastrophic', 'critical', 'major', 'moderate', 'minor'];
      const validPriorities = ['immediate', 'high', 'medium', 'low'];
      const validRiskLevels = ['critical', 'high', 'medium', 'low', 'secure'] as const;

      const top5Risks: CyberRisk[] = (parsed.top5Risks || []).slice(0, 5).map((risk: Record<string, unknown>, index: number): CyberRisk => ({
        rank: index + 1,
        id: typeof risk.id === 'string' ? risk.id : `RISK-${String(index + 1).padStart(3, '0')}`,
        title: typeof risk.title === 'string' ? risk.title : 'Security Risk',
        category: validCategories.includes(risk.category as RiskCategory) 
          ? risk.category as RiskCategory 
          : 'compute_security',
        severity: validSeverities.includes(risk.severity as Severity) 
          ? risk.severity as Severity 
          : 'medium',
        cvssScore: typeof risk.cvssScore === 'number' 
          ? Math.min(10, Math.max(0, risk.cvssScore)) 
          : 5.0,
        likelihood: validLikelihoods.includes(risk.likelihood as string) 
          ? risk.likelihood as CyberRisk['likelihood'] 
          : 'medium',
        impact: validImpacts.includes(risk.impact as string) 
          ? risk.impact as CyberRisk['impact'] 
          : 'moderate',
        description: typeof risk.description === 'string' 
          ? risk.description 
          : 'Risk identified by AI analysis',
        affectedMisconfigurations: Array.isArray(risk.affectedMisconfigurations) 
          ? risk.affectedMisconfigurations as string[] 
          : [],
        attackVector: typeof risk.attackVector === 'string' 
          ? risk.attackVector 
          : 'Attack vector analysis pending',
        potentialImpact: typeof risk.potentialImpact === 'string' 
          ? risk.potentialImpact 
          : 'Impact assessment pending',
        businessImpact: typeof risk.businessImpact === 'string' 
          ? risk.businessImpact 
          : 'Business impact assessment pending',
        remediationPriority: validPriorities.includes(risk.remediationPriority as string) 
          ? risk.remediationPriority as CyberRisk['remediationPriority'] 
          : 'medium',
        remediationSteps: Array.isArray(risk.remediationSteps) 
          ? risk.remediationSteps as string[] 
          : ['Review and address the identified issue'],
        estimatedRemediationTime: typeof risk.estimatedRemediationTime === 'string' 
          ? risk.estimatedRemediationTime 
          : 'Unknown',
        references: Array.isArray(risk.references) 
          ? risk.references as string[] 
          : []
      }));

      return {
        overallRiskScore: typeof parsed.overallRiskScore === 'number' 
          ? Math.min(100, Math.max(0, parsed.overallRiskScore)) 
          : 50,
        riskLevel: validRiskLevels.includes(parsed.riskLevel as typeof validRiskLevels[number])
          ? parsed.riskLevel as typeof validRiskLevels[number]
          : 'medium',
        top5Risks,
        complianceScore: typeof parsed.complianceScore === 'number' 
          ? Math.min(100, Math.max(0, parsed.complianceScore)) 
          : 50,
        recommendations: Array.isArray(parsed.recommendations) 
          ? parsed.recommendations.filter((r): r is string => typeof r === 'string')
          : ['Review security posture and implement recommended changes']
      };
    } catch (error) {
      console.error('[RiskAnalysis] Failed to parse LLM response:', error);
      throw new Error('Failed to parse LLM response. Please try again.');
    }
  }

  /**
   * Check if LLM service is available
   */
  async isServerAvailable(): Promise<boolean> {
    try {
      // Try a simple test call
      const result = await this.callLLM([
        { role: 'user', content: 'Say "OK" if you can respond.' }
      ]);
      return result !== null;
    } catch {
      return false;
    }
  }

  /**
   * Get available models
   */
  async getAvailableModels(): Promise<string[]> {
    return ['llama-3.3-70b', 'gpt-4', 'claude-3-sonnet'];
  }

  /**
   * Set the model to use
   */
  setModel(modelName: string): void {
    this.modelName = modelName;
  }
}

// Export singleton instance
export const riskEngine = new RiskAnalysisEngine();
