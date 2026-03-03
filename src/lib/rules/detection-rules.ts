/**
 * Misconfiguration Detection Rules Engine
 * Comprehensive rules for detecting VM security misconfigurations
 * Based on CIS Benchmarks, NIST Controls, and Industry Best Practices
 */

import { 
  VMInstance, 
  Misconfiguration, 
  Severity, 
  RiskCategory,
  SecurityGroupRule,
  SecurityGroup
} from './cloud/types';

// ============================================================================
// Rule Definitions
// ============================================================================

export interface DetectionRule {
  id: string;
  name: string;
  category: RiskCategory;
  severity: Severity;
  description: string;
  cisBenchmark?: string;
  nistControl?: string;
  mitreAttack?: string[];
  check: (vm: VMInstance) => Misconfiguration | null;
}

// ============================================================================
// Network Security Rules
// ============================================================================

const networkSecurityRules: DetectionRule[] = [
  {
    id: 'NS-001',
    name: 'SSH Port Open to Internet',
    category: 'network_security',
    severity: 'critical',
    description: 'SSH port (22) is open to the entire internet (0.0.0.0/0), allowing unrestricted access to the VM',
    cisBenchmark: 'CIS AWS 5.1',
    nistControl: 'NIST SC-7',
    mitreAttack: ['T1021.004', 'T1190'],
    check: (vm: VMInstance): Misconfiguration | null => {
      for (const sg of vm.securityGroups) {
        for (const rule of sg.rules) {
          if (rule.direction === 'inbound' && 
              rule.protocol.toLowerCase() === 'tcp' &&
              rule.fromPort === 22 &&
              rule.toPort === 22 &&
              (rule.source === '0.0.0.0/0' || rule.source === '::/0')) {
            return {
              id: `MISC-${vm.id}-${sg.id}-ssh`,
              ruleId: 'NS-001',
              ruleName: 'SSH Port Open to Internet',
              category: 'network_security',
              severity: 'critical',
              title: 'SSH port exposed to the internet',
              description: `Security group ${sg.name} allows SSH access from any IP address (0.0.0.0/0). This exposes the VM to brute force attacks and unauthorized access attempts.`,
              affectedResource: `Security Group: ${sg.name}`,
              currentValue: 'SSH (22) open to 0.0.0.0/0',
              recommendedValue: 'SSH (22) restricted to specific IP ranges or VPN',
              remediation: 'Restrict SSH access to known IP addresses or use a bastion host/VPN. Consider using AWS Systems Manager Session Manager for secure access without opening SSH ports.',
              references: [
                'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html',
                'https://www.cisecurity.org/benchmark/amazon_web_services'
              ],
              cisBenchmark: 'CIS AWS 5.1',
              nistControl: 'NIST SC-7',
              mitreAttackTactics: ['T1021.004', 'T1190']
            };
          }
        }
      }
      return null;
    }
  },
  {
    id: 'NS-002',
    name: 'RDP Port Open to Internet',
    category: 'network_security',
    severity: 'critical',
    description: 'RDP port (3389) is open to the entire internet, exposing Windows VMs to attacks',
    cisBenchmark: 'CIS AWS 5.2',
    nistControl: 'NIST SC-7',
    mitreAttack: ['T1021.001', 'T1190'],
    check: (vm: VMInstance): Misconfiguration | null => {
      for (const sg of vm.securityGroups) {
        for (const rule of sg.rules) {
          if (rule.direction === 'inbound' && 
              rule.protocol.toLowerCase() === 'tcp' &&
              rule.fromPort === 3389 &&
              rule.toPort === 3389 &&
              (rule.source === '0.0.0.0/0' || rule.source === '::/0')) {
            return {
              id: `MISC-${vm.id}-${sg.id}-rdp`,
              ruleId: 'NS-002',
              ruleName: 'RDP Port Open to Internet',
              category: 'network_security',
              severity: 'critical',
              title: 'RDP port exposed to the internet',
              description: `Security group ${sg.name} allows RDP access from any IP address. This exposes Windows VMs to brute force attacks, BlueKeep exploits, and credential theft.`,
              affectedResource: `Security Group: ${sg.name}`,
              currentValue: 'RDP (3389) open to 0.0.0.0/0',
              recommendedValue: 'RDP (3389) restricted to specific IP ranges or VPN',
              remediation: 'Restrict RDP access to known IP addresses. Use VPN or Azure Bastion for secure access. Enable Network Level Authentication (NLA).',
              references: [
                'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/rdp',
                'https://www.cisecurity.org/benchmark/azure'
              ],
              cisBenchmark: 'CIS AWS 5.2',
              nistControl: 'NIST SC-7',
              mitreAttackTactics: ['T1021.001', 'T1190']
            };
          }
        }
      }
      return null;
    }
  },
  {
    id: 'NS-003',
    name: 'Public IP Assigned',
    category: 'network_security',
    severity: 'high',
    description: 'VM has a public IP address assigned, making it directly accessible from the internet',
    cisBenchmark: 'CIS AWS 5.3',
    nistControl: 'NIST SC-7',
    mitreAttack: ['T1190'],
    check: (vm: VMInstance): Misconfiguration | null => {
      const hasPublicIp = vm.networkInterfaces.some(ni => ni.publicIpAssigned);
      if (hasPublicIp) {
        return {
          id: `MISC-${vm.id}-publicip`,
          ruleId: 'NS-003',
          ruleName: 'Public IP Assigned',
          category: 'network_security',
          severity: 'high',
          title: 'VM has public IP address',
          description: `VM ${vm.name} has a public IP address assigned, making it directly accessible from the internet. This increases the attack surface and potential exposure to threats.`,
          affectedResource: `Network Interface on VM: ${vm.name}`,
          currentValue: 'Public IP assigned',
          recommendedValue: 'No public IP or use NAT Gateway/Load Balancer',
          remediation: 'Remove public IP if not required. Use NAT Gateway for outbound internet access. Place VMs behind a Load Balancer or Application Gateway for incoming traffic.',
          references: [
            'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html',
            'https://docs.microsoft.com/en-us/azure/virtual-network/nat-overview'
          ],
          cisBenchmark: 'CIS AWS 5.3',
          nistControl: 'NIST SC-7',
          mitreAttackTactics: ['T1190']
        };
      }
      return null;
    }
  },
  {
    id: 'NS-004',
    name: 'Default Security Group In Use',
    category: 'network_security',
    severity: 'medium',
    description: 'VM is using the default security group which may have overly permissive rules',
    cisBenchmark: 'CIS AWS 5.4',
    nistControl: 'NIST CM-6',
    check: (vm: VMInstance): Misconfiguration | null => {
      const defaultSg = vm.securityGroups.find(sg => sg.isDefault);
      if (defaultSg) {
        return {
          id: `MISC-${vm.id}-defaultsg`,
          ruleId: 'NS-004',
          ruleName: 'Default Security Group In Use',
          category: 'network_security',
          severity: 'medium',
          title: 'Default security group is attached to VM',
          description: `VM ${vm.name} is using the default security group. Default security groups often have broad rules that may not align with least-privilege access principles.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'Default security group attached',
          recommendedValue: 'Custom security group with minimal required permissions',
          remediation: 'Create a custom security group with only the necessary inbound/outbound rules. Remove the default security group association.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/default-custom-security-groups.html'
          ],
          cisBenchmark: 'CIS AWS 5.4',
          nistControl: 'NIST CM-6'
        };
      }
      return null;
    }
  },
  {
    id: 'NS-005',
    name: 'All Ports Open to Internet',
    category: 'network_security',
    severity: 'critical',
    description: 'All TCP/UDP ports are open to the internet',
    cisBenchmark: 'CIS AWS 5.5',
    nistControl: 'NIST SC-7',
    mitreAttack: ['T1190', 'T1566'],
    check: (vm: VMInstance): Misconfiguration | null => {
      for (const sg of vm.securityGroups) {
        for (const rule of sg.rules) {
          if (rule.direction === 'inbound' && 
              (rule.source === '0.0.0.0/0' || rule.source === '::/0') &&
              (rule.fromPort === 0 || rule.fromPort === -1) &&
              (rule.toPort === 65535 || rule.toPort === -1)) {
            return {
              id: `MISC-${vm.id}-${sg.id}-allports`,
              ruleId: 'NS-005',
              ruleName: 'All Ports Open to Internet',
              category: 'network_security',
              severity: 'critical',
              title: 'All ports exposed to the internet',
              description: `Security group ${sg.name} allows all TCP/UDP ports from any IP address. This is extremely dangerous and exposes all services to potential exploitation.`,
              affectedResource: `Security Group: ${sg.name}`,
              currentValue: 'All ports (0-65535) open to 0.0.0.0/0',
              recommendedValue: 'Only required ports open to specific IP ranges',
              remediation: 'Immediately remove this rule and implement strict port restrictions. Only allow ports required for legitimate business purposes.',
              references: [
                'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html'
              ],
              cisBenchmark: 'CIS AWS 5.5',
              nistControl: 'NIST SC-7',
              mitreAttackTactics: ['T1190', 'T1566']
            };
          }
        }
      }
      return null;
    }
  }
];

// ============================================================================
// Identity & Access Rules
// ============================================================================

const identityAccessRules: DetectionRule[] = [
  {
    id: 'IA-001',
    name: 'No IAM Role Attached',
    category: 'identity_access',
    severity: 'high',
    description: 'VM does not have an IAM role attached, but may need one for proper operation',
    cisBenchmark: 'CIS AWS 1.22',
    nistControl: 'NIST AC-2',
    check: (vm: VMInstance): Misconfiguration | null => {
      if (!vm.iamRole) {
        return {
          id: `MISC-${vm.id}-norole`,
          ruleId: 'IA-001',
          ruleName: 'No IAM Role Attached',
          category: 'identity_access',
          severity: 'high',
          title: 'No IAM role attached to VM',
          description: `VM ${vm.name} does not have an IAM role attached. If the VM needs to access cloud services, credentials might be hardcoded, which is a security risk.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'No IAM role',
          recommendedValue: 'IAM role with least-privilege permissions',
          remediation: 'Attach an IAM role with only the permissions required for the VM to function. Avoid hardcoding credentials in applications.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html'
          ],
          cisBenchmark: 'CIS AWS 1.22',
          nistControl: 'NIST AC-2'
        };
      }
      return null;
    }
  },
  {
    id: 'IA-002',
    name: 'Overly Permissive IAM Role',
    category: 'identity_access',
    severity: 'critical',
    description: 'IAM role has overly permissive policies (e.g., AdministratorAccess)',
    cisBenchmark: 'CIS AWS 1.16',
    nistControl: 'NIST AC-6',
    mitreAttack: ['T1078', 'T1098'],
    check: (vm: VMInstance): Misconfiguration | null => {
      if (vm.iamRole) {
        for (const policy of vm.iamRole.policies) {
          const policyStr = JSON.stringify(policy.document).toLowerCase();
          if (policyStr.includes('action": "*"') || 
              policyStr.includes('administratoraccess') ||
              policyStr.includes('"*:*"')) {
            return {
              id: `MISC-${vm.id}-${vm.iamRole.id}-perm`,
              ruleId: 'IA-002',
              ruleName: 'Overly Permissive IAM Role',
              category: 'identity_access',
              severity: 'critical',
              title: 'IAM role has administrator or wildcard permissions',
              description: `VM ${vm.name} has an IAM role (${vm.iamRole.name}) with overly permissive permissions. If compromised, attackers could gain full control over cloud resources.`,
              affectedResource: `IAM Role: ${vm.iamRole.name}`,
              currentValue: 'Administrator or wildcard (*) permissions',
              recommendedValue: 'Least-privilege permissions specific to VM function',
              remediation: 'Review and restrict IAM role permissions to only those actions required by applications running on the VM. Implement permission boundaries.',
              references: [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege'
              ],
              cisBenchmark: 'CIS AWS 1.16',
              nistControl: 'NIST AC-6',
              mitreAttackTactics: ['T1078', 'T1098']
            };
          }
        }
      }
      return null;
    }
  },
  {
    id: 'IA-003',
    name: 'Instance Metadata Service V1',
    category: 'identity_access',
    severity: 'critical',
    description: 'VM is using IMDSv1 which is vulnerable to SSRF attacks',
    cisBenchmark: 'CIS AWS 1.200',
    nistControl: 'NIST SC-8',
    mitreAttack: ['T1552.005'],
    check: (vm: VMInstance): Misconfiguration | null => {
      if (!vm.metadataServiceV2) {
        return {
          id: `MISC-${vm.id}-imds`,
          ruleId: 'IA-003',
          ruleName: 'Instance Metadata Service V1',
          category: 'identity_access',
          severity: 'critical',
          title: 'IMDSv1 is enabled (SSRF vulnerable)',
          description: `VM ${vm.name} is using Instance Metadata Service version 1, which is vulnerable to Server-Side Request Forgery (SSRF) attacks. Attackers can steal IAM credentials through SSRF vulnerabilities.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'IMDSv1 enabled',
          recommendedValue: 'IMDSv2 required (IMDSv1 disabled)',
          remediation: 'Enable IMDSv2 and require its use. Set HttpTokens to required. This prevents SSRF-based credential theft attacks.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
            'https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/'
          ],
          cisBenchmark: 'CIS AWS 1.200',
          nistControl: 'NIST SC-8',
          mitreAttackTactics: ['T1552.005']
        };
      }
      return null;
    }
  }
];

// ============================================================================
// Data Protection Rules
// ============================================================================

const dataProtectionRules: DetectionRule[] = [
  {
    id: 'DP-001',
    name: 'Unencrypted Boot Disk',
    category: 'data_protection',
    severity: 'high',
    description: 'Boot disk is not encrypted at rest',
    cisBenchmark: 'CIS AWS 3.10',
    nistControl: 'NIST SC-28',
    check: (vm: VMInstance): Misconfiguration | null => {
      const bootDisk = vm.disks.find(d => d.boot);
      if (bootDisk && !bootDisk.encrypted) {
        return {
          id: `MISC-${vm.id}-${bootDisk.id}-enc`,
          ruleId: 'DP-001',
          ruleName: 'Unencrypted Boot Disk',
          category: 'data_protection',
          severity: 'high',
          title: 'Boot disk is not encrypted',
          description: `VM ${vm.name} has an unencrypted boot disk. Data at rest is vulnerable to unauthorized access if the storage media is compromised or improperly disposed.`,
          affectedResource: `Disk: ${bootDisk.name}`,
          currentValue: 'Encryption disabled',
          recommendedValue: 'Encryption enabled with customer-managed key (CMK)',
          remediation: 'Enable encryption for the boot disk using a customer-managed key (CMK) for maximum control. Create a new encrypted volume and migrate data if necessary.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
            'https://docs.microsoft.com/en-us/azure/virtual-machines/disk-encryption'
          ],
          cisBenchmark: 'CIS AWS 3.10',
          nistControl: 'NIST SC-28'
        };
      }
      return null;
    }
  },
  {
    id: 'DP-002',
    name: 'Unencrypted Data Disk',
    category: 'data_protection',
    severity: 'high',
    description: 'Data disk is not encrypted at rest',
    cisBenchmark: 'CIS AWS 3.10',
    nistControl: 'NIST SC-28',
    check: (vm: VMInstance): Misconfiguration | null => {
      const dataDisks = vm.disks.filter(d => !d.boot);
      const unencrypted = dataDisks.filter(d => !d.encrypted);
      if (unencrypted.length > 0) {
        return {
          id: `MISC-${vm.id}-datadisk-enc`,
          ruleId: 'DP-002',
          ruleName: 'Unencrypted Data Disk',
          category: 'data_protection',
          severity: 'high',
          title: 'One or more data disks are not encrypted',
          description: `VM ${vm.name} has ${unencrypted.length} unencrypted data disk(s). Sensitive data stored on these disks is vulnerable to unauthorized access.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: `${unencrypted.length} unencrypted data disk(s)`,
          recommendedValue: 'All disks encrypted with customer-managed key',
          remediation: 'Enable encryption for all data disks. Use customer-managed keys for maximum control. Consider using disk encryption at the VM level as well.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html'
          ],
          cisBenchmark: 'CIS AWS 3.10',
          nistControl: 'NIST SC-28'
        };
      }
      return null;
    }
  },
  {
    id: 'DP-003',
    name: 'Sensitive Data in User Data',
    category: 'data_protection',
    severity: 'critical',
    description: 'User data contains potentially sensitive information (secrets, passwords, keys)',
    cisBenchmark: 'CIS AWS 1.23',
    nistControl: 'NIST SC-28',
    mitreAttack: ['T1552.001'],
    check: (vm: VMInstance): Misconfiguration | null => {
      if (vm.userDataSensitiveData) {
        return {
          id: `MISC-${vm.id}-userdata`,
          ruleId: 'DP-003',
          ruleName: 'Sensitive Data in User Data',
          category: 'data_protection',
          severity: 'critical',
          title: 'Sensitive data detected in user data',
          description: `VM ${vm.name} has sensitive data (secrets, passwords, or keys) in the user data field. User data is accessible to anyone with access to the VM or metadata service.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'Sensitive data in user data',
          recommendedValue: 'Use secrets manager or parameter store',
          remediation: 'Remove sensitive data from user data. Use AWS Secrets Manager, Parameter Store, or Azure Key Vault for secrets management. Rotate any exposed credentials immediately.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html',
            'https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html'
          ],
          cisBenchmark: 'CIS AWS 1.23',
          nistControl: 'NIST SC-28',
          mitreAttackTactics: ['T1552.001']
        };
      }
      return null;
    }
  }
];

// ============================================================================
// Monitoring & Logging Rules
// ============================================================================

const monitoringRules: DetectionRule[] = [
  {
    id: 'ML-001',
    name: 'Detailed Monitoring Disabled',
    category: 'monitoring_logging',
    severity: 'medium',
    description: 'Detailed monitoring is not enabled, limiting visibility into VM performance',
    cisBenchmark: 'CIS AWS 2.2',
    nistControl: 'NIST AU-2',
    check: (vm: VMInstance): Misconfiguration | null => {
      if (!vm.monitoring.detailedMonitoring) {
        return {
          id: `MISC-${vm.id}-monitor`,
          ruleId: 'ML-001',
          ruleName: 'Detailed Monitoring Disabled',
          category: 'monitoring_logging',
          severity: 'medium',
          title: 'Detailed monitoring is disabled',
          description: `VM ${vm.name} does not have detailed monitoring enabled. Basic monitoring provides metrics every 5 minutes, which may miss short-duration security events or anomalies.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'Basic monitoring (5-minute intervals)',
          recommendedValue: 'Detailed monitoring (1-minute intervals)',
          remediation: 'Enable detailed monitoring for faster detection of security incidents and performance issues. Consider using CloudWatch or Azure Monitor for comprehensive logging.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html'
          ],
          cisBenchmark: 'CIS AWS 2.2',
          nistControl: 'NIST AU-2'
        };
      }
      return null;
    }
  },
  {
    id: 'ML-002',
    name: 'VPC Flow Logs Disabled',
    category: 'monitoring_logging',
    severity: 'high',
    description: 'VPC Flow Logs are not enabled, limiting network traffic visibility',
    cisBenchmark: 'CIS AWS 3.9',
    nistControl: 'NIST AU-12',
    check: (vm: VMInstance): Misconfiguration | null => {
      if (!vm.monitoring.vpcFlowLogsEnabled) {
        return {
          id: `MISC-${vm.id}-flowlogs`,
          ruleId: 'ML-002',
          ruleName: 'VPC Flow Logs Disabled',
          category: 'monitoring_logging',
          severity: 'high',
          title: 'VPC Flow Logs are disabled',
          description: `VM ${vm.name} does not have VPC Flow Logs enabled. This limits the ability to investigate security incidents, analyze network traffic patterns, and detect anomalies.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'VPC Flow Logs disabled',
          recommendedValue: 'VPC Flow Logs enabled',
          remediation: 'Enable VPC Flow Logs for the VPC or subnet. Forward logs to CloudWatch Logs or S3 for analysis and retention. Use for security analysis and compliance.',
          references: [
            'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
          ],
          cisBenchmark: 'CIS AWS 3.9',
          nistControl: 'NIST AU-12'
        };
      }
      return null;
    }
  },
  {
    id: 'ML-003',
    name: 'CloudTrail/Activity Logs Disabled',
    category: 'monitoring_logging',
    severity: 'high',
    description: 'API activity logging is not enabled',
    cisBenchmark: 'CIS AWS 2.1',
    nistControl: 'NIST AU-2',
    check: (vm: VMInstance): Misconfiguration | null => {
      if (!vm.monitoring.cloudTrailEnabled) {
        return {
          id: `MISC-${vm.id}-cloudtrail`,
          ruleId: 'ML-003',
          ruleName: 'CloudTrail/Activity Logs Disabled',
          category: 'monitoring_logging',
          severity: 'high',
          title: 'API activity logging is disabled',
          description: `VM ${vm.name} does not have CloudTrail or activity logging enabled. This limits the ability to audit changes, investigate incidents, and maintain compliance.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'CloudTrail/Activity logs disabled',
          recommendedValue: 'CloudTrail/Activity logs enabled',
          remediation: 'Enable CloudTrail (AWS) or Activity Logs (Azure) to record all API calls and configuration changes. Ensure logs are stored securely and have appropriate retention.',
          references: [
            'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html'
          ],
          cisBenchmark: 'CIS AWS 2.1',
          nistControl: 'NIST AU-2'
        };
      }
      return null;
    }
  }
];

// ============================================================================
// Compute Security Rules
// ============================================================================

const computeSecurityRules: DetectionRule[] = [
  {
    id: 'CS-001',
    name: 'Backup Not Configured',
    category: 'compute_security',
    severity: 'high',
    description: 'VM does not have automated backup configured',
    nistControl: 'NIST CP-9',
    check: (vm: VMInstance): Misconfiguration | null => {
      if (!vm.backup.enabled) {
        return {
          id: `MISC-${vm.id}-backup`,
          ruleId: 'CS-001',
          ruleName: 'Backup Not Configured',
          category: 'compute_security',
          severity: 'high',
          title: 'Automated backup is not configured',
          description: `VM ${vm.name} does not have automated backup configured. In case of data loss, ransomware, or system failure, recovery will be difficult or impossible.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'Backup disabled',
          recommendedValue: 'Automated backup enabled with appropriate retention',
          remediation: 'Enable automated backups using AWS Backup, Azure Backup, or similar service. Configure appropriate retention periods and test restore procedures regularly.',
          references: [
            'https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html',
            'https://docs.microsoft.com/en-us/azure/backup/backup-overview'
          ],
          nistControl: 'NIST CP-9'
        };
      }
      return null;
    }
  },
  {
    id: 'CS-002',
    name: 'Secure Boot Disabled',
    category: 'compute_security',
    severity: 'medium',
    description: 'Secure Boot is not enabled, making VM vulnerable to boot-level attacks',
    nistControl: 'NIST SC-41',
    check: (vm: VMInstance): Misconfiguration | null => {
      if (!vm.secureBoot) {
        return {
          id: `MISC-${vm.id}-secureboot`,
          ruleId: 'CS-002',
          ruleName: 'Secure Boot Disabled',
          category: 'compute_security',
          severity: 'medium',
          title: 'Secure Boot is not enabled',
          description: `VM ${vm.name} does not have Secure Boot enabled. This makes the VM vulnerable to bootkits, rootkits, and other boot-level malware that can bypass OS security controls.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: 'Secure Boot disabled',
          recommendedValue: 'Secure Boot enabled',
          remediation: 'Enable Secure Boot if the OS supports it. This ensures only signed, trusted boot components are loaded during startup.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/uefi-secure-boot.html',
            'https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot'
          ],
          nistControl: 'NIST SC-41'
        };
      }
      return null;
    }
  },
  {
    id: 'CS-003',
    name: 'No Tagging Policy',
    category: 'compute_security',
    severity: 'low',
    description: 'VM lacks required tags for security and governance',
    nistControl: 'NIST CM-8',
    check: (vm: VMInstance): Misconfiguration | null => {
      const requiredTags = ['Environment', 'Owner', 'Application', 'CostCenter'];
      const missingTags = requiredTags.filter(tag => !vm.tags[tag]);
      if (missingTags.length > 0) {
        return {
          id: `MISC-${vm.id}-tags`,
          ruleId: 'CS-003',
          ruleName: 'No Tagging Policy',
          category: 'compute_security',
          severity: 'low',
          title: 'VM lacks required tags',
          description: `VM ${vm.name} is missing required tags: ${missingTags.join(', ')}. Proper tagging is essential for security governance, cost management, and incident response.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: `Missing tags: ${missingTags.join(', ')}`,
          recommendedValue: `All required tags present: ${requiredTags.join(', ')}`,
          remediation: 'Apply required tags to all resources. Implement tag policies to enforce tagging standards. Use tags for access control, cost allocation, and automation.',
          references: [
            'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_tag-policies.html'
          ],
          nistControl: 'NIST CM-8'
        };
      }
      return null;
    }
  },
  {
    id: 'CS-004',
    name: 'Disk Not Deleted on Termination',
    category: 'compute_security',
    severity: 'medium',
    description: 'Disk is not set to be deleted when VM is terminated',
    nistControl: 'NIST MP-6',
    check: (vm: VMInstance): Misconfiguration | null => {
      const persistentDisks = vm.disks.filter(d => !d.deleteOnTermination);
      if (persistentDisks.length > 0) {
        return {
          id: `MISC-${vm.id}-diskdelete`,
          ruleId: 'CS-004',
          ruleName: 'Disk Not Deleted on Termination',
          category: 'compute_security',
          severity: 'medium',
          title: 'Disks persist after VM termination',
          description: `VM ${vm.name} has ${persistentDisks.length} disk(s) that will not be deleted on termination. This may lead to data leakage, unnecessary costs, and compliance issues.`,
          affectedResource: `VM: ${vm.name}`,
          currentValue: `${persistentDisks.length} disk(s) persist after termination`,
          recommendedValue: 'Non-essential disks deleted on termination',
          remediation: 'Configure disks to be deleted on termination unless they contain data that must be preserved. Implement data lifecycle policies for any retained disks.',
          references: [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html'
          ],
          nistControl: 'NIST MP-6'
        };
      }
      return null;
    }
  }
];

// ============================================================================
// All Rules Combined
// ============================================================================

export const allDetectionRules: DetectionRule[] = [
  ...networkSecurityRules,
  ...identityAccessRules,
  ...dataProtectionRules,
  ...monitoringRules,
  ...computeSecurityRules
];

// ============================================================================
// Rule Engine Functions
// ============================================================================

export function scanVMForMisconfigurations(vm: VMInstance): Misconfiguration[] {
  const misconfigurations: Misconfiguration[] = [];
  
  for (const rule of allDetectionRules) {
    try {
      const result = rule.check(vm);
      if (result) {
        misconfigurations.push(result);
      }
    } catch (error) {
      console.error(`Error applying rule ${rule.id}:`, error);
    }
  }
  
  // Sort by severity
  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  };
  
  return misconfigurations.sort((a, b) => 
    severityOrder[a.severity] - severityOrder[b.severity]
  );
}

export function getRulesByCategory(category: RiskCategory): DetectionRule[] {
  return allDetectionRules.filter(rule => rule.category === category);
}

export function getRulesBySeverity(severity: Severity): DetectionRule[] {
  return allDetectionRules.filter(rule => rule.severity === severity);
}

export function getRuleById(ruleId: string): DetectionRule | undefined {
  return allDetectionRules.find(rule => rule.id === ruleId);
}
