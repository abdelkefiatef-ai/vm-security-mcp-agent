/**
 * LLM-Based Risk Analysis Engine
 * Uses AI to analyze VM misconfigurations and generate Top-5 Cyber Risk Reports
 */

import ZAI from 'z-ai-web-dev-sdk';
import {
  VMInstance,
  Misconfiguration,
  CyberRisk,
  VMSecurityReport,
  RiskCategory,
  Severity
} from './cloud/types';

// ============================================================================
// Risk Analysis Types
// ============================================================================

interface RiskAnalysisInput {
  vm: VMInstance;
  misconfigurations: Misconfiguration[];
}

interface RiskGenerationPrompt {
  vmInfo: string;
  misconfigurationSummary: string;
  detailedMisconfigurations: string;
}

// ============================================================================
// Risk Analysis Engine Class
// ============================================================================

export class RiskAnalysisEngine {
  private zai: Awaited<ReturnType<typeof ZAI.create>> | null = null;

  async initialize(): Promise<void> {
    if (!this.zai) {
      this.zai = await ZAI.create();
    }
  }

  /**
   * Generate Top-5 Cyber Risks for a VM based on misconfigurations
   */
  async generateTop5Risks(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<CyberRisk[]> {
    await this.initialize();

    if (misconfigurations.length === 0) {
      return [];
    }

    const prompt = this.buildRiskAnalysisPrompt(vm, misconfigurations);
    
    const completion = await this.zai!.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `You are a senior cybersecurity analyst specializing in cloud infrastructure security. Your task is to analyze VM misconfigurations and identify the TOP 5 most critical cyber risks.

For each risk, you must provide:
1. A clear, actionable title
2. The category (network_security, identity_access, data_protection, monitoring_logging, compliance, or compute_security)
3. Severity level (critical, high, medium, low)
4. CVSS score (0.0-10.0)
5. Likelihood assessment (very_high, high, medium, low, very_low)
6. Impact assessment (catastrophic, critical, major, moderate, minor)
7. Detailed description of the risk
8. Attack vector explanation
9. Potential business impact
10. Remediation priority (immediate, high, medium, low)
11. Step-by-step remediation guidance
12. Estimated remediation time

Focus on real-world attack scenarios and practical recommendations. Prioritize risks that are most likely to be exploited and have the highest impact.

Respond ONLY with a valid JSON array containing exactly 5 risks (or fewer if there are fewer misconfigurations). Use this exact format:
[
  {
    "rank": 1,
    "id": "RISK-001",
    "title": "...",
    "category": "...",
    "severity": "...",
    "cvssScore": 9.8,
    "likelihood": "high",
    "impact": "critical",
    "description": "...",
    "affectedMisconfigurations": ["MISC-xxx"],
    "attackVector": "...",
    "potentialImpact": "...",
    "businessImpact": "...",
    "remediationPriority": "immediate",
    "remediationSteps": ["step1", "step2"],
    "estimatedRemediationTime": "...",
    "references": ["..."]
  }
]`
        },
        {
          role: 'user',
          content: prompt.vmInfo + '\n\n' + prompt.misconfigurationSummary + '\n\n' + prompt.detailedMisconfigurations
        }
      ],
      temperature: 0.3,
      max_tokens: 4000
    });

    const responseContent = completion.choices[0]?.message?.content || '';
    
    try {
      // Extract JSON from response
      const jsonMatch = responseContent.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        const risks: CyberRisk[] = JSON.parse(jsonMatch[0]);
        return this.validateAndEnrichRisks(risks, misconfigurations);
      }
    } catch (error) {
      console.error('Error parsing LLM response:', error);
      // Fall back to rule-based risk generation
      return this.generateRuleBasedRisks(misconfigurations);
    }

    return this.generateRuleBasedRisks(misconfigurations);
  }

  /**
   * Generate a complete security report for a VM
   */
  async generateSecurityReport(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<VMSecurityReport> {
    const top5Risks = await this.generateTop5Risks(vm, misconfigurations);
    
    const riskScore = this.calculateOverallRiskScore(misconfigurations, top5Risks);
    const riskLevel = this.determineRiskLevel(riskScore);
    const complianceScore = this.calculateComplianceScore(misconfigurations);
    const recommendations = await this.generateRecommendations(vm, misconfigurations, top5Risks);

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
      recommendations
    };
  }

  /**
   * Build the prompt for risk analysis
   */
  private buildRiskAnalysisPrompt(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): RiskGenerationPrompt {
    const vmInfo = `
## Virtual Machine Information

**Name:** ${vm.name}
**ID:** ${vm.id}
**Provider:** ${vm.provider.toUpperCase()}
**Region:** ${vm.region}
**Availability Zone:** ${vm.availabilityZone}
**Instance Type:** ${vm.instanceType}
**State:** ${vm.state}

### Network Configuration
- Public IP Assigned: ${vm.networkInterfaces.some(ni => ni.publicIpAssigned) ? 'Yes' : 'No'}
- Security Groups: ${vm.securityGroups.map(sg => sg.name).join(', ')}
- Network Interfaces: ${vm.networkInterfaces.length}

### Storage Configuration
- Total Disks: ${vm.disks.length}
- Encrypted Disks: ${vm.disks.filter(d => d.encrypted).length}/${vm.disks.length}
- Boot Disk Encrypted: ${vm.disks.find(d => d.boot)?.encrypted ? 'Yes' : 'No'}

### Identity & Access
- IAM Role Attached: ${vm.iamRole ? 'Yes (' + vm.iamRole.name + ')' : 'No'}
- IMDSv2 Enabled: ${vm.metadataServiceV2 ? 'Yes' : 'No'}

### Monitoring & Backup
- Detailed Monitoring: ${vm.monitoring.detailedMonitoring ? 'Enabled' : 'Disabled'}
- VPC Flow Logs: ${vm.monitoring.vpcFlowLogsEnabled ? 'Enabled' : 'Disabled'}
- CloudTrail/Activity Logs: ${vm.monitoring.cloudTrailEnabled ? 'Enabled' : 'Disabled'}
- Backup Configured: ${vm.backup.enabled ? 'Yes' : 'No'}

### Security Features
- Secure Boot: ${vm.secureBoot ? 'Enabled' : 'Disabled'}
- vTPM: ${vm.vtpmEnabled ? 'Enabled' : 'Disabled'}
- Sensitive Data in User Data: ${vm.userDataSensitiveData ? 'Detected' : 'None detected'}
`;

    const misconfigurationSummary = `
## Misconfiguration Summary

**Total Misconfigurations Found:** ${misconfigurations.length}

### By Severity:
- Critical: ${misconfigurations.filter(m => m.severity === 'critical').length}
- High: ${misconfigurations.filter(m => m.severity === 'high').length}
- Medium: ${misconfigurations.filter(m => m.severity === 'medium').length}
- Low: ${misconfigurations.filter(m => m.severity === 'low').length}

### By Category:
- Network Security: ${misconfigurations.filter(m => m.category === 'network_security').length}
- Identity & Access: ${misconfigurations.filter(m => m.category === 'identity_access').length}
- Data Protection: ${misconfigurations.filter(m => m.category === 'data_protection').length}
- Monitoring & Logging: ${misconfigurations.filter(m => m.category === 'monitoring_logging').length}
- Compute Security: ${misconfigurations.filter(m => m.category === 'compute_security').length}
`;

    const detailedMisconfigurations = `
## Detailed Misconfigurations

${misconfigurations.map((m, i) => `
### ${i + 1}. ${m.title} [${m.severity.toUpperCase()}]
- **Rule ID:** ${m.ruleId}
- **Category:** ${m.category}
- **Affected Resource:** ${m.affectedResource}
- **Current Value:** ${m.currentValue}
- **Recommended Value:** ${m.recommendedValue}
- **Description:** ${m.description}
- **Remediation:** ${m.remediation}
- **CIS Benchmark:** ${m.cisBenchmark || 'N/A'}
- **NIST Control:** ${m.nistControl || 'N/A'}
`).join('\n')}

Based on the above misconfigurations, generate the TOP 5 most critical cyber risks for this VM. Consider:
1. Attack feasibility and likelihood
2. Business impact and data exposure potential
3. Compliance implications
4. Chained attack scenarios
5. Real-world threat actor behaviors
`;

    return { vmInfo, misconfigurationSummary, detailedMisconfigurations };
  }

  /**
   * Validate and enrich risks with additional metadata
   */
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

    return risks.slice(0, 5).map((risk, index) => ({
      rank: index + 1,
      id: risk.id || `RISK-${String(index + 1).padStart(3, '0')}`,
      title: risk.title || 'Unknown Risk',
      category: validCategories.includes(risk.category) ? risk.category : 'compute_security',
      severity: validSeverities.includes(risk.severity) ? risk.severity : 'medium',
      cvssScore: Math.min(10, Math.max(0, risk.cvssScore || 5.0)),
      likelihood: validLikelihoods.includes(risk.likelihood) ? risk.likelihood : 'medium',
      impact: validImpacts.includes(risk.impact) ? risk.impact : 'moderate',
      description: risk.description || 'Risk description not available',
      affectedMisconfigurations: risk.affectedMisconfigurations || [],
      attackVector: risk.attackVector || 'Unknown attack vector',
      potentialImpact: risk.potentialImpact || 'Potential impact not determined',
      businessImpact: risk.businessImpact || 'Business impact not determined',
      remediationPriority: validPriorities.includes(risk.remediationPriority) 
        ? risk.remediationPriority : 'medium',
      remediationSteps: Array.isArray(risk.remediationSteps) ? risk.remediationSteps : [],
      estimatedRemediationTime: risk.estimatedRemediationTime || 'Unknown',
      references: Array.isArray(risk.references) ? risk.references : []
    }));
  }

  /**
   * Generate rule-based risks as fallback
   */
  private generateRuleBasedRisks(misconfigurations: Misconfiguration[]): CyberRisk[] {
    const severityToScore: Record<Severity, number> = {
      critical: 9.5,
      high: 7.5,
      medium: 5.0,
      low: 3.0,
      info: 1.0
    };

    const groupedMisco = this.groupMisconfigurationsBySeverity(misconfigurations);
    
    return misconfigurations.slice(0, 5).map((m, i) => ({
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
      attackVector: `Exploitation of ${m.title.toLowerCase()}`,
      potentialImpact: `Potential compromise through ${m.category.replace('_', ' ')}`,
      businessImpact: `Risk of data breach or service disruption`,
      remediationPriority: m.severity === 'critical' ? 'immediate' :
                          m.severity === 'high' ? 'high' : 'medium',
      remediationSteps: [m.remediation],
      estimatedRemediationTime: m.severity === 'critical' ? '1-2 hours' :
                               m.severity === 'high' ? '4-8 hours' : '1-2 days',
      references: m.references
    }));
  }

  /**
   * Calculate overall risk score (0-100)
   */
  private calculateOverallRiskScore(
    misconfigurations: Misconfiguration[],
    risks: CyberRisk[]
  ): number {
    if (misconfigurations.length === 0) return 100; // Secure

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

    // Base score from misconfigurations
    let score = Math.max(0, 100 - totalPenalty);

    // Adjust based on top risks
    if (risks.length > 0) {
      const avgCvss = risks.reduce((sum, r) => sum + r.cvssScore, 0) / risks.length;
      score = Math.min(score, Math.round(100 - (avgCvss * 8)));
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Determine risk level based on score
   */
  private determineRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'secure' {
    if (score < 30) return 'critical';
    if (score < 50) return 'high';
    if (score < 70) return 'medium';
    if (score < 90) return 'low';
    return 'secure';
  }

  /**
   * Calculate compliance score
   */
  private calculateComplianceScore(misconfigurations: Misconfiguration[]): number {
    const totalRules = 18; // Total number of detection rules
    const passedRules = totalRules - misconfigurations.length;
    return Math.round((passedRules / totalRules) * 100);
  }

  /**
   * Generate actionable recommendations
   */
  private async generateRecommendations(
    vm: VMInstance,
    misconfigurations: Misconfiguration[],
    risks: CyberRisk[]
  ): Promise<string[]> {
    const recommendations: string[] = [];

    // Priority-based recommendations
    const criticalMisco = misconfigurations.filter(m => m.severity === 'critical');
    const highMisco = misconfigurations.filter(m => m.severity === 'high');

    if (criticalMisco.length > 0) {
      recommendations.push(
        `URGENT: Address ${criticalMisco.length} critical misconfiguration(s) immediately - ` +
        criticalMisco.map(m => m.title).join(', ')
      );
    }

    if (highMisco.length > 0) {
      recommendations.push(
        `High Priority: Remediate ${highMisco.length} high-severity issue(s) within 24-48 hours`
      );
    }

    // Category-based recommendations
    const networkIssues = misconfigurations.filter(m => m.category === 'network_security');
    if (networkIssues.length > 0) {
      recommendations.push(
        'Network Security: Review and restrict security group rules. Implement network segmentation.'
      );
    }

    const iamIssues = misconfigurations.filter(m => m.category === 'identity_access');
    if (iamIssues.length > 0) {
      recommendations.push(
        'Identity & Access: Implement least-privilege access. Enable IMDSv2 and rotate credentials.'
      );
    }

    const dataIssues = misconfigurations.filter(m => m.category === 'data_protection');
    if (dataIssues.length > 0) {
      recommendations.push(
        'Data Protection: Enable encryption for all storage. Move secrets to dedicated vaults.'
      );
    }

    const monitoringIssues = misconfigurations.filter(m => m.category === 'monitoring_logging');
    if (monitoringIssues.length > 0) {
      recommendations.push(
        'Monitoring & Logging: Enable comprehensive logging and set up security alerts.'
      );
    }

    // General best practices
    recommendations.push(
      'Implement automated compliance scanning and continuous monitoring.',
      'Create an incident response plan for security events.',
      'Regular security training for team members managing cloud resources.'
    );

    return recommendations;
  }

  /**
   * Group misconfigurations by severity
   */
  private groupMisconfigurationsBySeverity(
    misconfigurations: Misconfiguration[]
  ): Record<Severity, Misconfiguration[]> {
    return {
      critical: misconfigurations.filter(m => m.severity === 'critical'),
      high: misconfigurations.filter(m => m.severity === 'high'),
      medium: misconfigurations.filter(m => m.severity === 'medium'),
      low: misconfigurations.filter(m => m.severity === 'low'),
      info: misconfigurations.filter(m => m.severity === 'info')
    };
  }
}

// Export singleton instance
export const riskEngine = new RiskAnalysisEngine();
