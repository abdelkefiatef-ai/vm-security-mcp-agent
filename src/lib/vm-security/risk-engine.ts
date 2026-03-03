/**
 * Pure LLM-Based Risk Analysis Engine
 * Demo mode for Vercel deployment - generates realistic security analysis
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
// Risk Analysis Engine (Demo Mode for Vercel)
// ============================================================================

export class RiskAnalysisEngine {
  private modelName: string;

  constructor(modelName: string = 'llama-3.3-70b') {
    this.modelName = modelName;
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
    const analysis = this.generateAnalysis(vm, misconfigurations);

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
   * Generate Top-5 Cyber Risks
   */
  async generateTop5Risks(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): Promise<CyberRisk[]> {
    if (misconfigurations.length === 0) {
      return [];
    }
    return this.generateAnalysis(vm, misconfigurations).top5Risks;
  }

  /**
   * Generate comprehensive analysis based on misconfigurations
   */
  private generateAnalysis(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): {
    overallRiskScore: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
    top5Risks: CyberRisk[];
    complianceScore: number;
    recommendations: string[];
  } {
    // Calculate scores based on misconfigurations
    const criticalCount = misconfigurations.filter(m => m.severity === 'critical').length;
    const highCount = misconfigurations.filter(m => m.severity === 'high').length;
    const mediumCount = misconfigurations.filter(m => m.severity === 'medium').length;
    const lowCount = misconfigurations.filter(m => m.severity === 'low').length;

    // Calculate overall risk score (100 = secure, 0 = critical)
    let riskScore = 100;
    riskScore -= criticalCount * 25;
    riskScore -= highCount * 15;
    riskScore -= mediumCount * 8;
    riskScore -= lowCount * 3;
    riskScore = Math.max(0, Math.min(100, riskScore));

    // Determine risk level
    let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
    if (riskScore < 25) riskLevel = 'critical';
    else if (riskScore < 50) riskLevel = 'high';
    else if (riskScore < 70) riskLevel = 'medium';
    else if (riskScore < 90) riskLevel = 'low';
    else riskLevel = 'secure';

    // Calculate compliance score
    const complianceScore = Math.max(0, 100 - (criticalCount * 20 + highCount * 12 + mediumCount * 6 + lowCount * 2));

    // Generate Top 5 Risks
    const top5Risks = this.generateTop5RisksFromMisconfigs(vm, misconfigurations);

    // Generate recommendations
    const recommendations = this.generateRecommendations(misconfigurations);

    return {
      overallRiskScore: riskScore,
      riskLevel,
      top5Risks,
      complianceScore,
      recommendations
    };
  }

  /**
   * Generate Top 5 risks from misconfigurations
   */
  private generateTop5RisksFromMisconfigs(
    vm: VMInstance,
    misconfigurations: Misconfiguration[]
  ): CyberRisk[] {
    // Sort by severity and take top issues
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...misconfigurations].sort(
      (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    );

    const risks: CyberRisk[] = [];
    const riskTemplates = this.getRiskTemplates(vm);

    for (let i = 0; i < Math.min(5, sorted.length); i++) {
      const misco = sorted[i];
      const template = riskTemplates[misco.ruleId] || riskTemplates['default'];

      risks.push({
        rank: i + 1,
        id: `RISK-${String(i + 1).padStart(3, '0')}`,
        title: template.title.replace('{resource}', misco.affectedResource),
        category: misco.category as RiskCategory,
        severity: misco.severity,
        cvssScore: this.calculateCVSS(misco.severity),
        likelihood: this.getLikelihood(misco.severity),
        impact: this.getImpact(misco.severity),
        description: `${misco.description} This vulnerability affects ${misco.affectedResource} on VM ${vm.name}.`,
        affectedMisconfigurations: [misco.ruleId],
        attackVector: template.attackVector,
        potentialImpact: template.potentialImpact,
        businessImpact: template.businessImpact,
        remediationPriority: this.getPriority(misco.severity),
        remediationSteps: [misco.remediation, ...template.additionalSteps],
        estimatedRemediationTime: this.getRemediationTime(misco.severity),
        references: misco.references.length > 0 ? misco.references : ['https://www.cisecurity.org/benchmarks']
      });
    }

    return risks;
  }

  /**
   * Calculate CVSS score based on severity
   */
  private calculateCVSS(severity: Severity): number {
    const scores = { critical: 9.5, high: 8.0, medium: 5.5, low: 3.0, info: 0.0 };
    return scores[severity] || 5.0;
  }

  /**
   * Get likelihood based on severity
   */
  private getLikelihood(severity: Severity): 'very_high' | 'high' | 'medium' | 'low' | 'very_low' {
    const likelihoods: Record<Severity, 'very_high' | 'high' | 'medium' | 'low' | 'very_low'> = { 
      critical: 'very_high', 
      high: 'high', 
      medium: 'medium', 
      low: 'low', 
      info: 'very_low' 
    };
    return likelihoods[severity] || 'medium';
  }

  /**
   * Get impact based on severity
   */
  private getImpact(severity: Severity): 'catastrophic' | 'critical' | 'major' | 'moderate' | 'minor' {
    const impacts: Record<Severity, 'catastrophic' | 'critical' | 'major' | 'moderate' | 'minor'> = { 
      critical: 'catastrophic', 
      high: 'critical', 
      medium: 'major', 
      low: 'moderate', 
      info: 'minor' 
    };
    return impacts[severity] || 'moderate';
  }

  /**
   * Get priority based on severity
   */
  private getPriority(severity: Severity): 'immediate' | 'high' | 'medium' | 'low' {
    const priorities: Record<Severity, 'immediate' | 'high' | 'medium' | 'low'> = { 
      critical: 'immediate', 
      high: 'high', 
      medium: 'medium', 
      low: 'low', 
      info: 'low' 
    };
    return priorities[severity] || 'medium';
  }

  /**
   * Get remediation time estimate
   */
  private getRemediationTime(severity: Severity): string {
    const times: Record<Severity, string> = { 
      critical: '1-2 hours', 
      high: '2-4 hours', 
      medium: '4-8 hours', 
      low: '1-2 days', 
      info: '1 week' 
    };
    return times[severity] || '4-8 hours';
  }

  /**
   * Generate recommendations based on misconfigurations
   */
  private generateRecommendations(misconfigurations: Misconfiguration[]): string[] {
    const recommendations: string[] = [];
    
    const categories = new Set(misconfigurations.map(m => m.category));
    
    if (categories.has('network_security')) {
      recommendations.push('Review and restrict security group rules to follow least privilege principle');
      recommendations.push('Implement network segmentation and use private subnets for sensitive workloads');
    }
    
    if (categories.has('identity_access')) {
      recommendations.push('Implement IMDSv2 to prevent SSRF attacks and credential theft');
      recommendations.push('Apply IAM roles with least privilege permissions');
    }
    
    if (categories.has('data_protection')) {
      recommendations.push('Enable encryption at rest for all storage volumes');
      recommendations.push('Remove sensitive data from instance user data scripts');
    }
    
    if (categories.has('monitoring_logging')) {
      recommendations.push('Enable CloudTrail/Activity logs for audit compliance');
      recommendations.push('Enable VPC Flow Logs for network traffic analysis');
    }
    
    if (categories.has('compute_security')) {
      recommendations.push('Configure automated backups with appropriate retention policies');
      recommendations.push('Apply required tags for resource management and cost allocation');
    }

    recommendations.push('Establish a regular security review process to maintain compliance');
    
    return recommendations.slice(0, 8);
  }

  /**
   * Risk templates for detailed analysis
   */
  private getRiskTemplates(vm: VMInstance): Record<string, {
    title: string;
    attackVector: string;
    potentialImpact: string;
    businessImpact: string;
    additionalSteps: string[];
  }> {
    return {
      'NS-001': {
        title: 'Critical: Open Security Group Exposes {resource} to Internet',
        attackVector: 'Attackers can scan and directly access the VM from any IP address on the internet, enabling reconnaissance, exploitation attempts, and potential unauthorized access.',
        potentialImpact: 'Direct server compromise, data exfiltration, malware installation, and potential lateral movement to other infrastructure components.',
        businessImpact: 'Data breach, regulatory non-compliance (GDPR, HIPAA), service disruption, and potential ransomware attack. Estimated cost: $100K-$1M+.',
        additionalSteps: ['Restrict source IPs to known ranges', 'Implement VPN or bastion host access', 'Enable AWS GuardDuty for threat detection']
      },
      'NS-002': {
        title: 'Critical: SSH Port Open to Internet on {resource}',
        attackVector: 'Brute force attacks, credential stuffing, and exploitation of SSH vulnerabilities from any internet location.',
        potentialImpact: 'Unauthorized server access, complete system compromise, credential theft, and potential supply chain attack vector.',
        businessImpact: 'Complete infrastructure compromise, data breach, compliance violations, and potential ransomware deployment.',
        additionalSteps: ['Implement SSH key-based authentication only', 'Use AWS Systems Manager Session Manager', 'Enable fail2ban or similar intrusion prevention']
      },
      'NS-003': {
        title: 'Critical: RDP Port Exposes {resource} to Remote Attacks',
        attackVector: 'BlueKeep and other RDP exploits, brute force attacks, and pass-the-hash attacks from internet-connected attackers.',
        potentialImpact: 'Complete system takeover, credential harvesting, malware deployment, and network propagation.',
        businessImpact: 'Ransomware attack vector, data breach, operational disruption, and potential regulatory fines.',
        additionalSteps: ['Implement RD Gateway with MFA', 'Use VPN for RDP access', 'Enable Network Level Authentication']
      },
      'IA-001': {
        title: 'High: Missing IAM Role on {resource}',
        attackVector: 'Without proper IAM roles, applications may use hardcoded credentials or overly permissive policies.',
        potentialImpact: 'Credential exposure in code, unauthorized API access, and difficulty in access auditing.',
        businessImpact: 'Security blind spots, compliance gaps, potential credential leaks, and increased attack surface.',
        additionalSteps: ['Create purpose-specific IAM role', 'Implement instance profile', 'Audit application credential usage']
      },
      'IA-003': {
        title: 'High: Overly Permissive IAM Role on {resource}',
        attackVector: 'Compromised instance can leverage excessive permissions to access, modify, or delete resources.',
        potentialImpact: 'Lateral movement, data exfiltration, infrastructure destruction, and privilege escalation.',
        businessImpact: 'Breach of multiple systems, data loss, compliance violations, and extended incident response.',
        additionalSteps: ['Review and restrict IAM policy', 'Implement permission boundaries', 'Enable CloudTrail for monitoring']
      },
      'IA-004': {
        title: 'Critical: IMDSv1 Enabled - SSRF Vulnerability on {resource}',
        attackVector: 'Server-Side Request Forgery (SSRF) attacks can retrieve instance metadata including temporary IAM credentials.',
        potentialImpact: 'Credential theft, account takeover, unauthorized access to all resources the role can access.',
        businessImpact: 'Full account compromise, data breach across multiple services, major incident response required.',
        additionalSteps: ['Enforce IMDSv2 with hop limit of 1', 'Update applications to use IMDSv2', 'Audit for SSRF vulnerabilities']
      },
      'DP-001': {
        title: 'High: Unencrypted Boot Disk on {resource}',
        attackVector: 'Physical access to storage, snapshot exposure, or insider threat can access unencrypted data.',
        potentialImpact: 'Data exposure, credential harvesting from disk, compliance violations.',
        businessImpact: 'Data breach, regulatory fines (GDPR Article 32), loss of customer trust.',
        additionalSteps: ['Enable default EBS encryption', 'Migrate to encrypted volumes', 'Implement key rotation policy']
      },
      'DP-002': {
        title: 'High: Unencrypted Data Disks on {resource}',
        attackVector: 'Data at rest can be accessed through volume snapshots, physical access, or backup exposure.',
        potentialImpact: 'Sensitive data exposure, database credential theft, compliance violations.',
        businessImpact: 'Data breach notification requirements, regulatory fines, reputation damage.',
        additionalSteps: ['Enable encryption for all volumes', 'Use customer-managed KMS keys', 'Audit encryption status regularly']
      },
      'DP-003': {
        title: 'Critical: Sensitive Data Exposed in User Data on {resource}',
        attackVector: 'User data is accessible via IMDSv1 SSRF, instance console, or through snapshot sharing.',
        potentialImpact: 'Direct credential theft, database password exposure, API key compromise.',
        businessImpact: 'Immediate credential rotation required, potential breach already occurred, compliance violation.',
        additionalSteps: ['Move secrets to AWS Secrets Manager', 'Rotate all exposed credentials immediately', 'Audit for unauthorized access']
      },
      'ML-001': {
        title: 'Medium: Detailed Monitoring Disabled on {resource}',
        attackVector: 'Insufficient logging limits detection of security incidents and attack patterns.',
        potentialImpact: 'Delayed threat detection, incomplete incident forensics, compliance gaps.',
        businessImpact: 'Extended breach dwell time, regulatory audit failures, increased insurance premiums.',
        additionalSteps: ['Enable detailed monitoring', 'Configure CloudWatch alarms', 'Integrate with SIEM solution']
      },
      'ML-002': {
        title: 'Medium: VPC Flow Logs Disabled on {resource}',
        attackVector: 'Network-level attacks go undetected without flow log analysis.',
        potentialImpact: 'Undetected reconnaissance, data exfiltration, and lateral movement.',
        businessImpact: 'Compliance audit failures, extended incident response time, regulatory fines.',
        additionalSteps: ['Enable VPC Flow Logs', 'Configure log retention policy', 'Analyze for anomalies']
      },
      'ML-003': {
        title: 'Medium: CloudTrail Disabled - No Audit Trail for {resource}',
        attackVector: 'Attacker actions are not logged, enabling persistent access and data theft without detection.',
        potentialImpact: 'No forensic evidence, compliance violations, inability to determine breach scope.',
        businessImpact: 'Regulatory penalties, failed audits, inability to meet legal discovery requirements.',
        additionalSteps: ['Enable CloudTrail for all regions', 'Configure log file validation', 'Implement log encryption']
      },
      'CS-001': {
        title: 'Medium: No Backup Configured for {resource}',
        attackVector: 'Ransomware or accidental deletion results in permanent data loss.',
        potentialImpact: 'Complete data loss, extended downtime, potential business closure.',
        businessImpact: 'Revenue loss, customer churn, regulatory fines, potential business failure.',
        additionalSteps: ['Configure automated backups', 'Test backup restoration', 'Implement cross-region replication']
      },
      'CS-003': {
        title: 'Low: Missing Required Tags on {resource}',
        attackVector: 'Lack of ownership and environment tags complicates security operations.',
        potentialImpact: 'Delayed incident response, cost allocation issues, compliance gaps.',
        businessImpact: 'Audit failures, inefficient resource management, security blind spots.',
        additionalSteps: ['Implement tag policies', 'Automate tag enforcement', 'Regular compliance audits']
      },
      'CS-004': {
        title: 'High: Public IP Assigned to {resource}',
        attackVector: 'Direct internet exposure increases attack surface for reconnaissance and exploitation.',
        potentialImpact: 'Increased vulnerability to network attacks, scanning, and direct targeting.',
        businessImpact: 'Higher risk profile, increased security costs, potential for targeted attacks.',
        additionalSteps: ['Use NAT Gateway for outbound access', 'Place in private subnet', 'Implement WAF if public access required']
      },
      'default': {
        title: 'Security Issue Detected: {resource}',
        attackVector: 'This misconfiguration could be exploited by attackers to compromise system security.',
        potentialImpact: 'Potential unauthorized access, data exposure, or service disruption.',
        businessImpact: 'Security posture degradation, potential compliance violations, increased risk.',
        additionalSteps: ['Review and remediate the identified issue', 'Implement security best practices', 'Monitor for related issues']
      }
    };
  }

  /**
   * Check if service is available (always true in demo mode)
   */
  async isServerAvailable(): Promise<boolean> {
    return true;
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
