/**
 * VM Security Types and Models
 * Comprehensive type definitions for VM misconfiguration analysis
 */

// ============================================================================
// Core Types
// ============================================================================

export type CloudProvider = 'aws' | 'azure' | 'gcp' | 'on-premise';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskCategory = 
  | 'network_security' 
  | 'identity_access' 
  | 'data_protection' 
  | 'monitoring_logging'
  | 'compliance'
  | 'compute_security';

// ============================================================================
// VM Configuration Types
// ============================================================================

export interface NetworkInterface {
  id: string;
  name: string;
  subnetId: string;
  securityGroups: string[];
  publicIpAssigned: boolean;
  privateIp: string;
  publicIp?: string;
  isDefault: boolean;
}

export interface SecurityGroupRule {
  id: string;
  direction: 'inbound' | 'outbound';
  protocol: string;
  fromPort: number;
  toPort: number;
  source: string;
  description?: string;
}

export interface SecurityGroup {
  id: string;
  name: string;
  description: string;
  rules: SecurityGroupRule[];
  isDefault: boolean;
}

export interface StorageDisk {
  id: string;
  name: string;
  type: 'standard' | 'ssd' | 'premium_ssd' | 'ultra_disk';
  encrypted: boolean;
  encryptionKey?: string;
  sizeGB: number;
  boot: boolean;
  deleteOnTermination: boolean;
}

export interface IAMRole {
  id: string;
  name: string;
  policies: IAMPolicy[];
  permissionsBoundary?: string;
}

export interface IAMPolicy {
  name: string;
  type: 'managed' | 'inline';
  document: Record<string, unknown>;
}

export interface MonitoringConfig {
  detailedMonitoring: boolean;
  cloudWatchEnabled: boolean;
  cloudTrailEnabled: boolean;
  vpcFlowLogsEnabled: boolean;
  guardDutyEnabled: boolean;
  securityHubEnabled: boolean;
  alertingEnabled: boolean;
}

export interface IAMPolicyDetails {
  name: string;
  type: 'managed' | 'inline';
  document: {
    Version: string;
    Statement: Array<{
      Effect: 'Allow' | 'Deny';
      Action: string | string[];
      Resource: string | string[];
      Condition?: Record<string, unknown>;
    }>;
  };
}

export interface IAMRoleDetails {
  id: string;
  name: string;
  policies: IAMPolicyDetails[];
  permissionsBoundary?: string;
}

export interface BackupConfig {
  enabled: boolean;
  retentionDays: number;
  frequency: 'daily' | 'weekly' | 'monthly';
  crossRegionCopy: boolean;
  encryptionEnabled: boolean;
}

export interface VMInstance {
  id: string;
  name: string;
  provider: CloudProvider;
  region: string;
  availabilityZone: string;
  instanceType: string;
  state: 'running' | 'stopped' | 'terminated' | 'pending';
  
  // Network
  networkInterfaces: NetworkInterface[];
  securityGroups: SecurityGroup[];
  
  // Storage
  disks: StorageDisk[];
  
  // Identity
  iamRole?: IAMRole;
  
  // Monitoring
  monitoring: MonitoringConfig;
  
  // Backup
  backup: BackupConfig;
  
  // Metadata
  tags: Record<string, string>;
  createdAt: string;
  launchTime: string;
  
  // Security-specific configurations
  metadataServiceV2: boolean;
  secureBoot: boolean;
  vtpmEnabled: boolean;
  
  // User data/scripts
  userData?: string;
  userDataSensitiveData: boolean;
}

// ============================================================================
// Misconfiguration Types
// ============================================================================

export interface Misconfiguration {
  id: string;
  ruleId: string;
  ruleName: string;
  category: RiskCategory;
  severity: Severity;
  title: string;
  description: string;
  affectedResource: string;
  currentValue: string;
  recommendedValue: string;
  remediation: string;
  references: string[];
  cisBenchmark?: string;
  nistControl?: string;
  mitreAttackTactics?: string[];
}

// ============================================================================
// Cyber Risk Types
// ============================================================================

export interface CyberRisk {
  rank: number;
  id: string;
  title: string;
  category: RiskCategory;
  severity: Severity;
  cvssScore: number;
  likelihood: 'very_high' | 'high' | 'medium' | 'low' | 'very_low';
  impact: 'catastrophic' | 'critical' | 'major' | 'moderate' | 'minor';
  description: string;
  affectedMisconfigurations: string[];
  attackVector: string;
  potentialImpact: string;
  businessImpact: string;
  remediationPriority: 'immediate' | 'high' | 'medium' | 'low';
  remediationSteps: string[];
  estimatedRemediationTime: string;
  references: string[];
}

export interface VMSecurityReport {
  vmId: string;
  vmName: string;
  provider: CloudProvider;
  region: string;
  scanTimestamp: string;
  overallRiskScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  misconfigurations: Misconfiguration[];
  top5Risks: CyberRisk[];
  complianceScore: number;
  recommendations: string[];
  analysisMetadata: {
    modelUsed: string;
    analysisDuration: number;
    rulesApplied: number;
  };
}

// ============================================================================
// MCP Tool Types
// ============================================================================

export interface MCPToolInput {
  action: 'scan' | 'analyze' | 'report' | 'list_vms' | 'get_vm';
  vmConfig?: VMInstance;
  vmId?: string;
}

export interface MCPToolOutput {
  success: boolean;
  data?: VMSecurityReport | CyberRisk[] | Misconfiguration[] | VMInstance[];
  error?: string;
  timestamp: string;
}
