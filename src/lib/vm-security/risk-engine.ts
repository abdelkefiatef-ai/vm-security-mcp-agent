/**
 * Local LLM-Based Risk Analysis Engine
 * Uses Ollama with Llama for analyzing VM misconfigurations and generating Top-5 Cyber Risks
 */

import { OllamaClient, ollamaClient } from '../ollama-client';
import {
  VMInstance,
  Misconfiguration,
  CyberRisk,
  VMSecurityReport,
  RiskCategory,
  Severity
} from './types';

// ============================================================================
// Risk Analysis Engine
// ============================================================================

export class RiskAnalysisEngine {
  private ollama: OllamaClient;
  private modelName: string;

  constructor(modelName: string = 'llama3.2') {
    this.ollama = ollamaClient;
    this.modelName = modelName;
  }

  /**
   * Generate Top-5 Cyber Risks using Local Llama LLM
   */
  async generateTop5Risks(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<CyberRisk[]> {
    if (misconfigurations.length === 0) {
      return [];
    }

    const startTime = Date.now();
    
    try {
      const prompt = this.buildRiskAnalysisPrompt(vm, misconfigurations);
      
      const response = await this.ollama.generateJSON<CyberRisk[]>(
        prompt,
        this.getSystemPrompt(),
        {
          model: this.modelName,
          temperature: 0.2,
          numPredict: 4096,
        }
      );

      console.log(`[RiskAnalysis] Generated risks in ${Date.now() - startTime}ms`);
      
      return this.validateAndEnrichRisks(response, misconfigurations);
    } catch (error) {
      console.error('[RiskAnalysis] LLM analysis failed, falling back to rule-based:', error);
      return this.generateRuleBasedRisks(misconfigurations);
    }
  }

  /**
   * Generate complete security report for a VM
   */
  async generateSecurityReport(
    vm: VMInstance,
    misconfigurations: Misconfiguration[],
    rulesApplied: number = 18
  ): Promise<VMSecurityReport> {
    const startTime = Date.now();
    
    const top5Risks = await this.generateTop5Risks(vm, misconfigurations);
    const riskScore = this.calculateOverallRiskScore(misconfigurations, top5Risks);
    const riskLevel = this.determineRiskLevel(riskScore);
    const complianceScore = this.calculateComplianceScore(misconfigurations);
    const recommendations = this.generateRecommendations(misconfigurations, top5Risks);

    return {
      vmId: vm.id,
      vmName: vm.name,
      provider: vm.provider,
      region: vm.region,
      scanTimestamp: new Date().toISOString(),
      overallRiskScore: riskScore,
      riskLevel,
      misconfigurations,
      top5Risks,
      complianceScore,
      recommendations,
      analysisMetadata: {
        modelUsed: this.modelName,
        analysisDuration: Date.now() - startTime,
        rulesApplied
      }
    };
  }

  /**
   * Check if Ollama server is available
   */
  async isServerAvailable(): Promise<boolean> {
    return this.ollama.isServerRunning();
  }

  /**
   * Get available models
   */
  async getAvailableModels(): Promise<string[]> {
    const models = await this.ollama.listModels();
    return models.map(m => m.name);
  }

  /**
   * Set the model to use
   */
  setModel(modelName: string): void {
    this.modelName = modelName;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private getSystemPrompt(): string {
    return `You are an elite cybersecurity analyst specializing in cloud infrastructure security, threat intelligence, and risk assessment. Your expertise includes:

- CIS Benchmarks and NIST Cybersecurity Framework
- MITRE ATT&CK framework and threat actor behaviors
- Cloud security best practices (AWS, Azure, GCP)
- Attack surface analysis and exploit chain identification
- Business impact assessment and risk prioritization

Your task is to analyze VM misconfigurations and identify the TOP 5 most critical cyber risks. For each risk:

1. Provide a clear, actionable title that security teams can understand
2. Assign appropriate severity based on exploitability and impact
3. Calculate realistic CVSS scores (0.0-10.0)
4. Describe realistic attack vectors and exploitation scenarios
5. Assess business impact beyond technical impact
6. Provide practical, step-by-step remediation guidance

IMPORTANT: You MUST respond with valid JSON only. No markdown, no code blocks, no explanations outside the JSON array.`;
  }

  private buildRiskAnalysisPrompt(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): string {
    const vmInfo = this.formatVMInfo(vm);
    const miscoSummary = this.formatMisconfigurationSummary(misconfigurations);
    const detailedMisco = this.formatDetailedMisconfigurations(misconfigurations);

    return `
${vmInfo}

${miscoSummary}

${detailedMisco}

Based on the above misconfigurations, generate the TOP 5 most critical cyber risks for this VM.

Consider these attack scenarios:
1. External attackers scanning for exposed services
2. SSRF attacks to steal instance credentials
3. Privilege escalation through overly permissive IAM roles
4. Data exfiltration through unencrypted storage
5. Persistence through boot-level compromises
6. Ransomware targeting unencrypted data disks
7. Lateral movement from compromised VMs

For each risk, output JSON in this exact format:
{
  "rank": 1,
  "id": "RISK-001",
  "title": "Clear actionable risk title",
  "category": "network_security|identity_access|data_protection|monitoring_logging|compliance|compute_security",
  "severity": "critical|high|medium|low",
  "cvssScore": 9.8,
  "likelihood": "very_high|high|medium|low|very_low",
  "impact": "catastrophic|critical|major|moderate|minor",
  "description": "Detailed risk description",
  "affectedMisconfigurations": ["MISC-xxx-xxx"],
  "attackVector": "How an attacker would exploit this",
  "potentialImpact": "Technical impact of exploitation",
  "businessImpact": "Business consequences",
  "remediationPriority": "immediate|high|medium|low",
  "remediationSteps": ["Step 1", "Step 2", "Step 3"],
  "estimatedRemediationTime": "2-4 hours",
  "references": ["https://reference"]
}

Output a JSON array with exactly 5 risks (or fewer if fewer misconfigurations exist), ordered by severity.`;
  }

  private formatVMInfo(vm: VMInstance): string {
    return `## Virtual Machine Information

**Name:** ${vm.name}
**ID:** ${vm.id}
**Provider:** ${vm.provider.toUpperCase()}
**Region:** ${vm.region}
**Instance Type:** ${vm.instanceType}
**State:** ${vm.state}

### Network Configuration
- Public IP: ${vm.networkInterfaces.some(ni => ni.publicIpAssigned) ? 'YES (Exposed to Internet)' : 'No (Internal Only)'}
- Security Groups: ${vm.securityGroups.map(sg => sg.name).join(', ')}

### Storage Configuration
- Total Disks: ${vm.disks.length}
- Encrypted Disks: ${vm.disks.filter(d => d.encrypted).length}/${vm.disks.length}

### Identity & Access
- IAM Role: ${vm.iamRole ? vm.iamRole.name : 'None'}
- IMDSv2: ${vm.metadataServiceV2 ? 'Enabled (Secure)' : 'Disabled (VULNERABLE to SSRF)'}
- Sensitive Data in User Data: ${vm.userDataSensitiveData ? 'YES (CRITICAL)' : 'No'}

### Monitoring & Backup
- Detailed Monitoring: ${vm.monitoring.detailedMonitoring ? 'Enabled' : 'Disabled'}
- VPC Flow Logs: ${vm.monitoring.vpcFlowLogsEnabled ? 'Enabled' : 'Disabled'}
- Backup: ${vm.backup.enabled ? 'Configured' : 'NOT Configured'}

### Security Features
- Secure Boot: ${vm.secureBoot ? 'Enabled' : 'Disabled'}
- vTPM: ${vm.vtpmEnabled ? 'Enabled' : 'Disabled'}`;
  }

  private formatMisconfigurationSummary(misco: Misconfiguration[]): string {
    return `## Misconfiguration Summary

**Total Misconfigurations:** ${misco.length}

### By Severity:
- 🔴 Critical: ${misco.filter(m => m.severity === 'critical').length}
- 🟠 High: ${misco.filter(m => m.severity === 'high').length}
- 🟡 Medium: ${misco.filter(m => m.severity === 'medium').length}
- 🟢 Low: ${misco.filter(m => m.severity === 'low').length}

### By Category:
- Network Security: ${misco.filter(m => m.category === 'network_security').length}
- Identity & Access: ${misco.filter(m => m.category === 'identity_access').length}
- Data Protection: ${misco.filter(m => m.category === 'data_protection').length}
- Monitoring & Logging: ${misco.filter(m => m.category === 'monitoring_logging').length}
- Compute Security: ${misco.filter(m => m.category === 'compute_security').length}`;
  }

  private formatDetailedMisconfigurations(misco: Misconfiguration[]): string {
    return `## Detailed Misconfigurations

${misco.map((m, i) => `
### ${i + 1}. ${m.title} [${m.severity.toUpperCase()}]
- **Rule ID:** ${m.ruleId}
- **Category:** ${m.category}
- **Affected Resource:** ${m.affectedResource}
- **Current State:** ${m.currentValue}
- **Should Be:** ${m.recommendedValue}
- **Description:** ${m.description}
- **Remediation:** ${m.remediation}
- **CIS Benchmark:** ${m.cisBenchmark || 'N/A'}
- **MITRE ATT&CK:** ${m.mitreAttackTactics?.join(', ') || 'N/A'}
`).join('\n')}`;
  }

  private validateAndEnrichRisks(
    risks: CyberRisk[],
    misconfigurations: Misconfiguration[]
  ): CyberRisk[] {
    const validCategories: RiskCategory[] = [
      'network_security', 'identity_access', 'data_protection',
      'monitoring_logging', 'compliance', 'compute_security'
    ];
    const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const validLikelihoods = ['very_high', 'high', 'medium', 'low', 'very_low'];
    const validImpacts = ['catastrophic', 'critical', 'major', 'moderate', 'minor'];
    const validPriorities = ['immediate', 'high', 'medium', 'low'];

    if (!Array.isArray(risks)) {
      return this.generateRuleBasedRisks(misconfigurations);
    }

    return risks.slice(0, 5).map((risk, index): CyberRisk => ({
      rank: index + 1,
      id: risk.id || `RISK-${String(index + 1).padStart(3, '0')}`,
      title: risk.title || 'Unknown Risk',
      category: validCategories.includes(risk.category) ? risk.category : 'compute_security',
      severity: validSeverities.includes(risk.severity) ? risk.severity : 'medium',
      cvssScore: Math.min(10, Math.max(0, risk.cvssScore || 5.0)),
      likelihood: validLikelihoods.includes(risk.likelihood) ? risk.likelihood : 'medium',
      impact: validImpacts.includes(risk.impact) ? risk.impact : 'moderate',
      description: risk.description || 'Risk description not available',
      affectedMisconfigurations: Array.isArray(risk.affectedMisconfigurations) 
        ? risk.affectedMisconfigurations 
        : [],
      attackVector: risk.attackVector || 'Unknown attack vector',
      potentialImpact: risk.potentialImpact || 'Potential impact not determined',
      businessImpact: risk.businessImpact || 'Business impact not determined',
      remediationPriority: validPriorities.includes(risk.remediationPriority) 
        ? risk.remediationPriority 
        : 'medium',
      remediationSteps: Array.isArray(risk.remediationSteps) && risk.remediationSteps.length > 0
        ? risk.remediationSteps 
        : ['Review and address the underlying misconfiguration'],
      estimatedRemediationTime: risk.estimatedRemediationTime || 'Unknown',
      references: Array.isArray(risk.references) ? risk.references : []
    }));
  }

  private generateRuleBasedRisks(misconfigurations: Misconfiguration[]): CyberRisk[] {
    const severityToScore: Record<Severity, number> = {
      critical: 9.5,
      high: 7.5,
      medium: 5.0,
      low: 3.0,
      info: 1.0
    };

    return misconfigurations.slice(0, 5).map((m, i): CyberRisk => ({
      rank: i + 1,
      id: `RISK-${String(i + 1).padStart(3, '0')}`,
      title: m.title,
      category: m.category,
      severity: m.severity,
      cvssScore: severityToScore[m.severity],
      likelihood: m.severity === 'critical' ? 'very_high' : 
                  m.severity === 'high' ? 'high' : 
                  m.severity === 'medium' ? 'medium' : 'low',
      impact: m.severity === 'critical' ? 'catastrophic' :
              m.severity === 'high' ? 'critical' :
              m.severity === 'medium' ? 'major' : 'moderate',
      description: m.description,
      affectedMisconfigurations: [m.id],
      attackVector: `Exploitation of ${m.title.toLowerCase()} - attackers can target the ${m.category.replace('_', ' ')} weakness to compromise the system.`,
      potentialImpact: `Successful exploitation could lead to unauthorized access, data breach, or service disruption through ${m.category.replace('_', ' ')} vulnerabilities.`,
      businessImpact: `This vulnerability may result in regulatory fines, reputational damage, operational disruption, and potential data breach notification requirements.`,
      remediationPriority: m.severity === 'critical' ? 'immediate' :
                          m.severity === 'high' ? 'high' : 'medium',
      remediationSteps: [m.remediation],
      estimatedRemediationTime: m.severity === 'critical' ? '1-2 hours' :
                               m.severity === 'high' ? '4-8 hours' : '1-2 days',
      references: m.references
    }));
  }

  private calculateOverallRiskScore(
    misconfigurations: Misconfiguration[],
    risks: CyberRisk[]
  ): number {
    if (misconfigurations.length === 0) return 100;

    const severityWeights: Record<Severity, number> = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3,
      info: 1
    };

    const totalPenalty = misconfigurations.reduce((sum, m) => {
      return sum + severityWeights[m.severity];
    }, 0);

    let score = Math.max(0, 100 - totalPenalty);

    if (risks.length > 0) {
      const avgCvss = risks.reduce((sum, r) => sum + r.cvssScore, 0) / risks.length;
      score = Math.min(score, Math.round(100 - (avgCvss * 8)));
    }

    return Math.max(0, Math.min(100, score));
  }

  private determineRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'secure' {
    if (score < 30) return 'critical';
    if (score < 50) return 'high';
    if (score < 70) return 'medium';
    if (score < 90) return 'low';
    return 'secure';
  }

  private calculateComplianceScore(misconfigurations: Misconfiguration[]): number {
    const totalRules = 18;
    const passedRules = totalRules - misconfigurations.length;
    return Math.round((passedRules / totalRules) * 100);
  }

  private generateRecommendations(
    misconfigurations: Misconfiguration[],
    risks: CyberRisk[]
  ): string[] {
    const recommendations: string[] = [];

    const criticalMisco = misconfigurations.filter(m => m.severity === 'critical');
    const highMisco = misconfigurations.filter(m => m.severity === 'high');

    if (criticalMisco.length > 0) {
      recommendations.push(
        `🔴 CRITICAL: Immediately address ${criticalMisco.length} critical issue(s): ` +
        criticalMisco.map(m => m.title).join(', ')
      );
    }

    if (highMisco.length > 0) {
      recommendations.push(
        `🟠 HIGH: Remediate ${highMisco.length} high-severity issue(s) within 24-48 hours`
      );
    }

    // Category-based recommendations
    const categories = new Set(misconfigurations.map(m => m.category));
    
    if (categories.has('network_security')) {
      recommendations.push(
        '🌐 Network Security: Implement network segmentation, restrict security groups to least privilege, consider using a WAF.'
      );
    }
    
    if (categories.has('identity_access')) {
      recommendations.push(
        '🔑 Identity & Access: Enable IMDSv2, implement least-privilege IAM policies, rotate credentials.'
      );
    }
    
    if (categories.has('data_protection')) {
      recommendations.push(
        '🔐 Data Protection: Enable encryption at rest using customer-managed keys, move secrets to dedicated vaults.'
      );
    }
    
    if (categories.has('monitoring_logging')) {
      recommendations.push(
        '📊 Monitoring: Enable comprehensive logging (CloudTrail, VPC Flow Logs), set up security alerts.'
      );
    }

    recommendations.push(
      '📋 Implement automated compliance scanning and continuous monitoring.',
      '🛡️ Create an incident response plan and conduct regular security training.'
    );

    return recommendations;
  }
}

// Export singleton instance
export const riskEngine = new RiskAnalysisEngine();
