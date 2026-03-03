/**
 * Sample VM Data Generator
 * Creates realistic VM configurations for demonstration and testing
 */

import {
  VMInstance,
  CloudProvider
} from './types';

// ============================================================================
// Sample VM Configurations
// ============================================================================

function createSampleVM(
  id: string, 
  name: string, 
  securityPosture: 'critical' | 'high' | 'medium' | 'low' | 'secure',
  provider: CloudProvider = 'aws'
): VMInstance {
  const baseVM: VMInstance = {
    id: `i-${id}`,
    name,
    provider,
    region: 'us-east-1',
    availabilityZone: 'us-east-1a',
    instanceType: 't3.xlarge',
    state: 'running',
    networkInterfaces: [],
    securityGroups: [],
    disks: [],
    monitoring: {
      detailedMonitoring: false,
      cloudWatchEnabled: false,
      cloudTrailEnabled: false,
      vpcFlowLogsEnabled: false,
      guardDutyEnabled: false,
      securityHubEnabled: false,
      alertingEnabled: false
    },
    backup: {
      enabled: false,
      retentionDays: 0,
      frequency: 'daily',
      crossRegionCopy: false,
      encryptionEnabled: false
    },
    tags: {},
    createdAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    launchTime: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    metadataServiceV2: false,
    secureBoot: false,
    vtpmEnabled: false,
    userDataSensitiveData: false
  };

  switch (securityPosture) {
    case 'critical':
      return createCriticalPostureVM(baseVM);
    case 'high':
      return createHighRiskPostureVM(baseVM);
    case 'medium':
      return createMediumRiskPostureVM(baseVM);
    case 'low':
      return createLowRiskPostureVM(baseVM);
    case 'secure':
      return createSecurePostureVM(baseVM);
    default:
      return baseVM;
  }
}

function createCriticalPostureVM(base: VMInstance): VMInstance {
  return {
    ...base,
    networkInterfaces: [
      {
        id: `eni-${base.id}-1`,
        name: 'primary-network-interface',
        subnetId: 'subnet-0abc123',
        securityGroups: ['sg-critical001'],
        publicIpAssigned: true,
        privateIp: '10.0.1.50',
        publicIp: '54.123.45.67',
        isDefault: false
      }
    ],
    securityGroups: [
      {
        id: 'sg-critical001',
        name: 'default-security-group',
        description: 'Default security group',
        isDefault: true,
        rules: [
          {
            id: 'rule-001',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 0,
            toPort: 65535,
            source: '0.0.0.0/0',
            description: 'Allow all traffic - DANGEROUS'
          },
          {
            id: 'rule-002',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 22,
            toPort: 22,
            source: '0.0.0.0/0',
            description: 'SSH from anywhere'
          },
          {
            id: 'rule-003',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 3389,
            toPort: 3389,
            source: '0.0.0.0/0',
            description: 'RDP from anywhere'
          }
        ]
      }
    ],
    disks: [
      {
        id: `vol-${base.id}-root`,
        name: 'root-volume',
        type: 'standard',
        encrypted: false,
        sizeGB: 100,
        boot: true,
        deleteOnTermination: false
      },
      {
        id: `vol-${base.id}-data`,
        name: 'data-volume',
        type: 'ssd',
        encrypted: false,
        sizeGB: 500,
        boot: false,
        deleteOnTermination: false
      }
    ],
    iamRole: {
      id: 'role-admin001',
      name: 'AdministratorAccess-Role',
      policies: [
        {
          name: 'AdministratorAccess',
          type: 'managed',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*'
              }
            ]
          }
        }
      ]
    },
    monitoring: {
      detailedMonitoring: false,
      cloudWatchEnabled: false,
      cloudTrailEnabled: false,
      vpcFlowLogsEnabled: false,
      guardDutyEnabled: false,
      securityHubEnabled: false,
      alertingEnabled: false
    },
    backup: {
      enabled: false,
      retentionDays: 0,
      frequency: 'daily',
      crossRegionCopy: false,
      encryptionEnabled: false
    },
    tags: {
      Name: base.name
    },
    metadataServiceV2: false,
    secureBoot: false,
    vtpmEnabled: false,
    userDataSensitiveData: true
  };
}

function createHighRiskPostureVM(base: VMInstance): VMInstance {
  return {
    ...base,
    networkInterfaces: [
      {
        id: `eni-${base.id}-1`,
        name: 'primary-network-interface',
        subnetId: 'subnet-0abc124',
        securityGroups: ['sg-high001'],
        publicIpAssigned: true,
        privateIp: '10.0.1.51',
        publicIp: '54.123.45.68',
        isDefault: false
      }
    ],
    securityGroups: [
      {
        id: 'sg-high001',
        name: 'web-server-sg',
        description: 'Security group for web servers',
        isDefault: false,
        rules: [
          {
            id: 'rule-001',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 22,
            toPort: 22,
            source: '0.0.0.0/0',
            description: 'SSH access from anywhere'
          },
          {
            id: 'rule-002',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 80,
            toPort: 80,
            source: '0.0.0.0/0',
            description: 'HTTP access'
          },
          {
            id: 'rule-003',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 443,
            toPort: 443,
            source: '0.0.0.0/0',
            description: 'HTTPS access'
          }
        ]
      }
    ],
    disks: [
      {
        id: `vol-${base.id}-root`,
        name: 'root-volume',
        type: 'ssd',
        encrypted: false,
        sizeGB: 100,
        boot: true,
        deleteOnTermination: true
      }
    ],
    iamRole: {
      id: 'role-web001',
      name: 'WebServerRole',
      policies: [
        {
          name: 'S3FullAccess',
          type: 'managed',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
              }
            ]
          }
        }
      ]
    },
    monitoring: {
      detailedMonitoring: false,
      cloudWatchEnabled: true,
      cloudTrailEnabled: false,
      vpcFlowLogsEnabled: false,
      guardDutyEnabled: false,
      securityHubEnabled: false,
      alertingEnabled: false
    },
    backup: {
      enabled: false,
      retentionDays: 0,
      frequency: 'daily',
      crossRegionCopy: false,
      encryptionEnabled: false
    },
    tags: {
      Name: base.name,
      Environment: 'Production'
    },
    metadataServiceV2: false,
    secureBoot: false,
    vtpmEnabled: false,
    userDataSensitiveData: false
  };
}

function createMediumRiskPostureVM(base: VMInstance): VMInstance {
  return {
    ...base,
    networkInterfaces: [
      {
        id: `eni-${base.id}-1`,
        name: 'primary-network-interface',
        subnetId: 'subnet-0abc125',
        securityGroups: ['sg-med001'],
        publicIpAssigned: false,
        privateIp: '10.0.2.50',
        isDefault: false
      }
    ],
    securityGroups: [
      {
        id: 'sg-med001',
        name: 'app-server-sg',
        description: 'Security group for application servers',
        isDefault: false,
        rules: [
          {
            id: 'rule-001',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 8080,
            toPort: 8080,
            source: '10.0.1.0/24',
            description: 'App port from web tier'
          },
          {
            id: 'rule-002',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 22,
            toPort: 22,
            source: '10.0.0.0/8',
            description: 'SSH from internal network'
          }
        ]
      }
    ],
    disks: [
      {
        id: `vol-${base.id}-root`,
        name: 'root-volume',
        type: 'ssd',
        encrypted: true,
        encryptionKey: 'aws/ecs',
        sizeGB: 50,
        boot: true,
        deleteOnTermination: true
      },
      {
        id: `vol-${base.id}-data`,
        name: 'data-volume',
        type: 'ssd',
        encrypted: false,
        sizeGB: 200,
        boot: false,
        deleteOnTermination: false
      }
    ],
    iamRole: {
      id: 'role-app001',
      name: 'ApplicationRole',
      policies: [
        {
          name: 'EC2ReadOnly',
          type: 'managed',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['ec2:Describe*', 'ec2:Get*'],
                Resource: '*'
              }
            ]
          }
        }
      ]
    },
    monitoring: {
      detailedMonitoring: true,
      cloudWatchEnabled: true,
      cloudTrailEnabled: true,
      vpcFlowLogsEnabled: false,
      guardDutyEnabled: false,
      securityHubEnabled: false,
      alertingEnabled: true
    },
    backup: {
      enabled: true,
      retentionDays: 30,
      frequency: 'daily',
      crossRegionCopy: false,
      encryptionEnabled: true
    },
    tags: {
      Name: base.name,
      Environment: 'Production',
      Application: 'BackendAPI',
      Owner: 'DevOps'
    },
    metadataServiceV2: true,
    secureBoot: false,
    vtpmEnabled: false,
    userDataSensitiveData: false
  };
}

function createLowRiskPostureVM(base: VMInstance): VMInstance {
  return {
    ...base,
    networkInterfaces: [
      {
        id: `eni-${base.id}-1`,
        name: 'primary-network-interface',
        subnetId: 'subnet-0abc126',
        securityGroups: ['sg-low001'],
        publicIpAssigned: false,
        privateIp: '10.0.3.50',
        isDefault: false
      }
    ],
    securityGroups: [
      {
        id: 'sg-low001',
        name: 'db-server-sg',
        description: 'Security group for database servers',
        isDefault: false,
        rules: [
          {
            id: 'rule-001',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 5432,
            toPort: 5432,
            source: '10.0.2.0/24',
            description: 'PostgreSQL from app tier'
          }
        ]
      }
    ],
    disks: [
      {
        id: `vol-${base.id}-root`,
        name: 'root-volume',
        type: 'premium_ssd',
        encrypted: true,
        encryptionKey: 'kms-db-key',
        sizeGB: 100,
        boot: true,
        deleteOnTermination: true
      },
      {
        id: `vol-${base.id}-data`,
        name: 'data-volume',
        type: 'premium_ssd',
        encrypted: true,
        encryptionKey: 'kms-db-key',
        sizeGB: 1000,
        boot: false,
        deleteOnTermination: false
      }
    ],
    iamRole: {
      id: 'role-db001',
      name: 'DatabaseRole',
      policies: [
        {
          name: 'SecretsManagerRead',
          type: 'managed',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['secretsmanager:GetSecretValue'],
                Resource: 'arn:aws:secretsmanager:*:*:secret:db-*'
              }
            ]
          }
        }
      ]
    },
    monitoring: {
      detailedMonitoring: true,
      cloudWatchEnabled: true,
      cloudTrailEnabled: true,
      vpcFlowLogsEnabled: true,
      guardDutyEnabled: true,
      securityHubEnabled: true,
      alertingEnabled: true
    },
    backup: {
      enabled: true,
      retentionDays: 90,
      frequency: 'daily',
      crossRegionCopy: true,
      encryptionEnabled: true
    },
    tags: {
      Name: base.name,
      Environment: 'Production',
      Application: 'PostgreSQL',
      Owner: 'DBA',
      CostCenter: 'Engineering'
    },
    metadataServiceV2: true,
    secureBoot: true,
    vtpmEnabled: true,
    userDataSensitiveData: false
  };
}

function createSecurePostureVM(base: VMInstance): VMInstance {
  return {
    ...base,
    networkInterfaces: [
      {
        id: `eni-${base.id}-1`,
        name: 'primary-network-interface',
        subnetId: 'subnet-0abc127',
        securityGroups: ['sg-sec001'],
        publicIpAssigned: false,
        privateIp: '10.0.4.50',
        isDefault: false
      }
    ],
    securityGroups: [
      {
        id: 'sg-sec001',
        name: 'secure-sg',
        description: 'Hardened security group',
        isDefault: false,
        rules: [
          {
            id: 'rule-001',
            direction: 'inbound',
            protocol: 'tcp',
            fromPort: 443,
            toPort: 443,
            source: '10.0.0.0/8',
            description: 'HTTPS from internal only'
          }
        ]
      }
    ],
    disks: [
      {
        id: `vol-${base.id}-root`,
        name: 'root-volume',
        type: 'premium_ssd',
        encrypted: true,
        encryptionKey: 'kms-customer-managed-key',
        sizeGB: 50,
        boot: true,
        deleteOnTermination: true
      }
    ],
    iamRole: {
      id: 'role-sec001',
      name: 'MinimalRole',
      policies: [
        {
          name: 'MinimalAccess',
          type: 'inline',
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['s3:GetObject'],
                Resource: 'arn:aws:s3:::secure-bucket/*'
              }
            ]
          }
        }
      ],
      permissionsBoundary: 'arn:aws:iam::aws:policy/RestrictiveBoundary'
    },
    monitoring: {
      detailedMonitoring: true,
      cloudWatchEnabled: true,
      cloudTrailEnabled: true,
      vpcFlowLogsEnabled: true,
      guardDutyEnabled: true,
      securityHubEnabled: true,
      alertingEnabled: true
    },
    backup: {
      enabled: true,
      retentionDays: 365,
      frequency: 'daily',
      crossRegionCopy: true,
      encryptionEnabled: true
    },
    tags: {
      Name: base.name,
      Environment: 'Production',
      Application: 'SecureService',
      Owner: 'SecurityTeam',
      CostCenter: 'Security',
      DataClassification: 'Confidential'
    },
    metadataServiceV2: true,
    secureBoot: true,
    vtpmEnabled: true,
    userDataSensitiveData: false
  };
}

// ============================================================================
// Sample VMs Collection
// ============================================================================

export const sampleVMs: VMInstance[] = [
  createSampleVM('0abc123def456', 'prod-web-server-01', 'critical'),
  createSampleVM('1def234abc567', 'prod-app-server-01', 'high'),
  createSampleVM('2ghi345def678', 'prod-db-server-01', 'medium'),
  createSampleVM('3jkl456ghi789', 'prod-cache-server-01', 'low'),
  createSampleVM('4mno567jkl890', 'prod-secure-api-01', 'secure'),
  createSampleVM('5pqr678mno901', 'dev-web-server-01', 'critical'),
  createSampleVM('6stu789pqr012', 'staging-app-01', 'high'),
  createSampleVM('7vwx890stu123', 'prod-worker-01', 'medium'),
];

export function getVMById(id: string): VMInstance | undefined {
  return sampleVMs.find(vm => vm.id === id || vm.id === `i-${id}`);
}

export function getVMsByProvider(provider: CloudProvider): VMInstance[] {
  return sampleVMs.filter(vm => vm.provider === provider);
}

export function getVMsByRegion(region: string): VMInstance[] {
  return sampleVMs.filter(vm => vm.region === region);
}

export function generateRandomVMs(
  count: number, 
  provider: CloudProvider = 'aws'
): VMInstance[] {
  const postures: Array<'critical' | 'high' | 'medium' | 'low' | 'secure'> = 
    ['critical', 'high', 'medium', 'low', 'secure'];
  
  return Array.from({ length: count }, (_, i) => {
    const posture = postures[Math.floor(Math.random() * postures.length)];
    return createSampleVM(
      `${Math.random().toString(36).substring(2, 14)}`,
      `vm-${provider}-${i + 1}`,
      posture,
      provider
    );
  });
}
