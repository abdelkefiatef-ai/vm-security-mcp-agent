/**
 * Pure LLM-Based Risk Analysis Engine
 * Fully autonomous AI-powered VM security analysis using Cloud LLM
 * No local installation required - uses cloud-based Llama
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
// Pure LLM Risk Analysis Engine (Cloud-Based)
// ============================================================================

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ZAIClient = any;

export class RiskAnalysisEngine {
  private modelName: string;
  private zai: ZAIClient = null;

  constructor(modelName: string = 'llama-3.3-70b') {
    this.modelName = modelName;
  }

  /**
   * Initialize the LLM client
   */
  private async initialize(): Promise<void> {
    if (!this.zai) {
      try {
        const ZAI = (await import('z-ai-web-dev-sdk')).default;
        this.zai = await ZAI.create();
      } catch (error) {
        console.error('[RiskAnalysis] Failed to initialize LLM:', error);
        throw new Error(`LLM initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  }

  /**
   * Generate complete security report using pure LLM analysis
   * No rule-based fallbacks - all analysis is AI-generated
   */
  async generateSecurityReport(
    vm: VMInstance,
    misconfigurations: Misconfiguration[],
    rulesApplied: number = 18
  ): Promise<VMSecurityReport> {
    const startTime = Date.now();
    
    await this.initialize();

    // Use LLM for comprehensive risk analysis
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
   * Generate Top-5 Cyber Risks using pure LLM analysis
   */
  async generateTop5Risks(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<CyberRisk[]> {
    if (misconfigurations.length === 0) {
      return [];
    }

    await this.initialize();
    const analysis = await this.performLLMAnalysis(vm, misconfigurations);
    return analysis.top5Risks;
  }

  /**
   * Core LLM Analysis - All security analysis is performed by the Cloud LLM
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

    try {
      const completion = await this.zai!.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: systemPrompt
          },
          {
            role: 'user',
            content: userPrompt
          }
        ],
        temperature: 0.3,
        max_tokens: 4096
      });

      const response = completion.choices[0]?.message?.content || '';
      return this.parseLLMResponse(response, misconfigurations);
    } catch (error) {
      console.error('[RiskAnalysis] LLM analysis error:', error);
      throw new Error(`LLM analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Security Analyst System Prompt
   */
  private getSecurityAnalystPrompt(): string {
    return `You are an elite cybersecurity analyst AI with deep expertise in:

**Cloud Security Domains:**
- AWS, Azure, GCP infrastructure security
- CIS Benchmarks and compliance frameworks (NIST, ISO 27001, SOC 2)
- MITRE ATT&CK framework and threat intelligence
- Zero-trust architecture and defense-in-depth strategies

**Your Analysis Capabilities:**
1. Attack vector identification and exploitation chain analysis
2. Business impact assessment with regulatory implications
3. Risk scoring using CVSS 3.1 methodology
4. Actionable remediation with prioritization

**Output Requirements:**
You MUST respond with ONLY valid JSON. No markdown, no explanations outside JSON.
Your response must be a single JSON object with this exact structure:

{
  "overallRiskScore": <number 0-100>,
  "riskLevel": "<critical|high|medium|low|secure>",
  "complianceScore": <number 0-100>,
  "top5Risks": [
    {
      "rank": <1-5>,
      "id": "RISK-001",
      "title": "<clear actionable title>",
      "category": "<network_security|identity_access|data_protection|monitoring_logging|compliance|compute_security>",
      "severity": "<critical|high|medium|low>",
      "cvssScore": <number 0.0-10.0>,
      "likelihood": "<very_high|high|medium|low|very_low>",
      "impact": "<catastrophic|critical|major|moderate|minor>",
      "description": "<detailed risk description>",
      "affectedMisconfigurations": ["<misconfiguration IDs>"],
      "attackVector": "<how attackers exploit this>",
      "potentialImpact": "<technical consequences>",
      "businessImpact": "<business and regulatory consequences>",
      "remediationPriority": "<immediate|high|medium|low>",
      "remediationSteps": ["<step 1>", "<step 2>"],
      "estimatedRemediationTime": "<time estimate>",
      "references": ["<reference URLs>"]
    }
  ],
  "recommendations": [
    "<recommendation 1>",
    "<recommendation 2>"
  ]
}

**Analysis Guidelines:**
- Score risks based on real-world exploitability, not theoretical possibilities
- Consider attack chains where multiple misconfigurations combine
- Factor in business context: regulated data, customer impact, operational criticality
- Provide specific, actionable remediation steps
- Include real attack scenarios from threat intelligence`;
  }

  /**
   * Build comprehensive analysis prompt for the LLM
   */
  private buildAnalysisPrompt(vm: VMInstance, misconfigurations: Misconfiguration[]): string {
    return `## Security Analysis Request

Analyze the following VM configuration and misconfigurations to generate a comprehensive security risk assessment.

### Virtual Machine Details

**Identity:**
- Name: ${vm.name}
- ID: ${vm.id}
- Provider: ${vm.provider.toUpperCase()}
- Region: ${vm.region}
- Availability Zone: ${vm.availabilityZone}
- Instance Type: ${vm.instanceType}
- State: ${vm.state}

**Network Configuration:**
- Public IP Assigned: ${vm.networkInterfaces.some(ni => ni.publicIpAssigned) ? 'YES (Internet Accessible)' : 'NO (Internal Only)'}
- Network Interfaces: ${vm.networkInterfaces.length}
- Security Groups: ${vm.securityGroups.map(sg => sg.name).join(', ')}

**Security Group Rules:**
${vm.securityGroups.map(sg => `
Group: ${sg.name} (${sg.isDefault ? 'DEFAULT' : 'Custom'})
${sg.rules.map(r => `  - ${r.direction}: ${r.protocol}:${r.fromPort}-${r.toPort} from ${r.source}`).join('\n')}
`).join('\n')}

**Storage Configuration:**
- Total Disks: ${vm.disks.length}
- Boot Disk Encrypted: ${vm.disks.find(d => d.boot)?.encrypted ? 'YES' : 'NO'}
- All Disks Encrypted: ${vm.disks.every(d => d.encrypted) ? 'YES' : 'NO'}
- Disk Details: ${vm.disks.map(d => `${d.name}(${d.encrypted ? 'encrypted' : 'unencrypted'})`).join(', ')}

**Identity & Access:**
- IAM Role: ${vm.iamRole ? vm.iamRole.name : 'NONE'}
- IAM Policies: ${vm.iamRole?.policies.map(p => p.name).join(', ') || 'N/A'}
- IMDSv2 Enabled: ${vm.metadataServiceV2 ? 'YES (Secure)' : 'NO (SSRF Vulnerable)'}
- Sensitive Data in User Data: ${vm.userDataSensitiveData ? 'DETECTED (CRITICAL)' : 'None detected'}

**Monitoring & Logging:**
- Detailed Monitoring: ${vm.monitoring.detailedMonitoring ? 'Enabled' : 'Disabled'}
- CloudTrail/Activity Logs: ${vm.monitoring.cloudTrailEnabled ? 'Enabled' : 'Disabled'}
- VPC Flow Logs: ${vm.monitoring.vpcFlowLogsEnabled ? 'Enabled' : 'Disabled'}
- Security Monitoring: ${vm.monitoring.guardDutyEnabled ? 'Enabled' : 'Disabled'}

**Backup & Recovery:**
- Backup Configured: ${vm.backup.enabled ? 'YES' : 'NO'}
- Retention: ${vm.backup.enabled ? `${vm.backup.retentionDays} days` : 'N/A'}
- Cross-Region: ${vm.backup.crossRegionCopy ? 'YES' : 'NO'}

**Security Features:**
- Secure Boot: ${vm.secureBoot ? 'Enabled' : 'Disabled'}
- vTPM: ${vm.vtpmEnabled ? 'Enabled' : 'Disabled'}

**Tags:**
${Object.entries(vm.tags).map(([k, v]) => `- ${k}: ${v}`).join('\n') || '- No tags applied'}

### Detected Misconfigurations (${misconfigurations.length} total)

${misconfigurations.map((m, i) => `
#### ${i + 1}. ${m.title} [${m.severity.toUpperCase()}]
- **Rule ID:** ${m.ruleId}
- **Category:** ${m.category}
- **Affected Resource:** ${m.affectedResource}
- **Current Configuration:** ${m.currentValue}
- **Secure Configuration:** ${m.recommendedValue}
- **Issue:** ${m.description}
- **CIS Benchmark:** ${m.cisBenchmark || 'N/A'}
- **NIST Control:** ${m.nistControl || 'N/A'}
- **MITRE ATT&CK:** ${m.mitreAttackTactics?.join(', ') || 'N/A'}
`).join('\n')}

### Analysis Instructions

1. **Analyze Attack Surface:** Consider how these misconfigurations could be chained by attackers
2. **Generate Top 5 Risks:** Prioritize by real-world exploitability and business impact
3. **Calculate Scores:** 
   - overallRiskScore: 0-100 (0=critical risk, 100=secure)
   - complianceScore: percentage of security best practices met
4. **Risk Level:** critical/high/medium/low/secure based on overallRiskScore
5. **Recommendations:** Specific, prioritized, actionable items

Respond with ONLY the JSON object, no other text.`;
  }

  /**
   * Parse LLM response into structured analysis
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

      // Validate and sanitize the response
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
      console.error('[RiskAnalysis] Raw response:', response);
      throw new Error('Failed to parse LLM response. Please try again.');
    }
  }

  /**
   * Check if LLM service is available
   */
  async isServerAvailable(): Promise<boolean> {
    try {
      await this.initialize();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get available models
   */
  async getAvailableModels(): Promise<string[]> {
    return ['llama-3.3-70b', 'llama-3.2-3b', 'mistral-large'];
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
