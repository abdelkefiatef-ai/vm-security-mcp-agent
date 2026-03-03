'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  Shield,
  AlertTriangle,
  Server,
  Activity,
  Brain,
  RefreshCw,
  ChevronRight,
  XCircle,
  CheckCircle,
  Info,
  Zap,
  Globe,
  Lock,
  Eye,
  FileText,
  Clock,
  Cpu,
  Database,
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'secure';

interface VMInfo {
  id: string;
  name: string;
  provider: string;
  region: string;
  state: string;
  instanceType: string;
  hasPublicIP: boolean;
  diskCount: number;
  encryptedDisks: number;
}

interface Misconfiguration {
  id: string;
  ruleId: string;
  ruleName: string;
  category: string;
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

interface CyberRisk {
  rank: number;
  id: string;
  title: string;
  category: string;
  severity: Severity;
  cvssScore: number;
  likelihood: string;
  impact: string;
  description: string;
  affectedMisconfigurations: string[];
  attackVector: string;
  potentialImpact: string;
  businessImpact: string;
  remediationPriority: string;
  remediationSteps: string[];
  estimatedRemediationTime: string;
  references: string[];
}

interface SecurityReport {
  vmId: string;
  vmName: string;
  provider: string;
  region: string;
  scanTimestamp: string;
  overallRiskScore: number;
  riskLevel: RiskLevel;
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

interface LLMStatus {
  status: string;
  availableModels: string[];
  message: string;
}

// ============================================================================
// Main Component
// ============================================================================

export default function VMSecurityAnalyzer() {
  // State
  const [vms, setVMs] = useState<VMInfo[]>([]);
  const [selectedVM, setSelectedVM] = useState<VMInfo | null>(null);
  const [scanResult, setScanResult] = useState<{ misconfigurations: Misconfiguration[] } | null>(null);
  const [securityReport, setSecurityReport] = useState<SecurityReport | null>(null);
  const [llmStatus, setLLMStatus] = useState<LLMStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedModel, setSelectedModel] = useState('llama-3.3-70b');
  const [error, setError] = useState<string | null>(null);

  // API Functions
  const scanVM = useCallback(async (vmId: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/vm-security?action=scan&vmId=${vmId}`);
      const data = await response.json();
      if (data.success) {
        setScanResult({ misconfigurations: data.misconfigurations });
      } else {
        setError(data.error || 'Scan failed');
      }
    } catch (err) {
      setError('Failed to scan VM');
    }
    setLoading(false);
  }, []);

  const analyzeRisks = useCallback(async (vmId: string, model: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/vm-security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'report',
          vmId,
          model,
        }),
      });
      const data = await response.json();
      if (data.success) {
        setSecurityReport(data.report);
        setActiveTab('report');
      } else {
        setError(data.error || 'Analysis failed');
      }
    } catch (err) {
      setError('Failed to analyze risks');
    }
    setLoading(false);
  }, []);

  // Fetch initial data on mount
  useEffect(() => {
    const controller = new AbortController();
    
    async function loadData() {
      try {
        const [vmResponse, llmResponse] = await Promise.all([
          fetch('/api/vm-security?action=list', { signal: controller.signal }),
          fetch('/api/vm-security?action=llm-status', { signal: controller.signal })
        ]);
        
        const vmData = await vmResponse.json();
        const llmData = await llmResponse.json();
        
        if (vmData.success) {
          setVMs(vmData.virtualMachines);
        }
        setLLMStatus(llmData);
      } catch (err) {
        if (!(err instanceof Error && err.name === 'AbortError')) {
          console.error('Failed to load data:', err);
        }
      }
    }
    
    loadData();
    
    return () => controller.abort();
  }, []);

  // Severity helpers
  const getSeverityColor = (severity: Severity) => {
    const colors = {
      critical: 'bg-red-500 text-white',
      high: 'bg-orange-500 text-white',
      medium: 'bg-yellow-500 text-black',
      low: 'bg-blue-500 text-white',
      info: 'bg-gray-500 text-white',
    };
    return colors[severity] || colors.info;
  };

  const getRiskLevelColor = (level: RiskLevel) => {
    const colors = {
      critical: 'bg-red-600 text-white',
      high: 'bg-orange-500 text-white',
      medium: 'bg-yellow-500 text-black',
      low: 'bg-green-500 text-white',
      secure: 'bg-emerald-600 text-white',
    };
    return colors[level] || colors.low;
  };

  const getRiskScoreColor = (score: number) => {
    if (score < 30) return 'text-red-500';
    if (score < 50) return 'text-orange-500';
    if (score < 70) return 'text-yellow-500';
    if (score < 90) return 'text-green-500';
    return 'text-emerald-500';
  };

  // Selected VM info
  const selectedVMFull = selectedVM ? vms.find(v => v.id === selectedVM.id) : null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">VM Security MCP Agent</h1>
                <p className="text-sm text-slate-400">Open-source LLM-powered Cyber Risk Analysis</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              {llmStatus && (
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span className="text-sm text-slate-300">
                    Cloud LLM Ready
                  </span>
                </div>
              )}
              <Select value={selectedModel} onValueChange={setSelectedModel}>
                <SelectTrigger className="w-36 bg-slate-800 border-slate-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="llama-3.3-70b">Llama 3.3 70B</SelectItem>
                  <SelectItem value="llama-3.2-3b">Llama 3.2 3B</SelectItem>
                  <SelectItem value="mistral-large">Mistral Large</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-6">
        <div className="grid grid-cols-12 gap-6">
          {/* VM List Sidebar */}
          <div className="col-span-3">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Server className="h-5 w-5" />
                  Virtual Machines
                </CardTitle>
                <CardDescription className="text-slate-400">
                  {vms.length} VMs available for analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[calc(100vh-280px)]">
                  <div className="space-y-2">
                    {vms.map((vm) => (
                      <button
                        key={vm.id}
                        onClick={() => {
                          setSelectedVM(vm);
                          setScanResult(null);
                          setSecurityReport(null);
                        }}
                        className={`w-full text-left p-3 rounded-lg transition-all ${
                          selectedVM?.id === vm.id
                            ? 'bg-blue-600/30 border border-blue-500'
                            : 'bg-slate-700/50 hover:bg-slate-700 border border-transparent'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex-1 min-w-0">
                            <p className="font-medium text-white truncate">{vm.name}</p>
                            <p className="text-xs text-slate-400">{vm.instanceType}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            {vm.hasPublicIP && (
                              <Globe className="h-4 w-4 text-orange-400" title="Public IP" />
                            )}
                            <Badge variant="outline" className="text-xs">
                              {vm.provider.toUpperCase()}
                            </Badge>
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          {/* Main Content */}
          <div className="col-span-9">
            {error && (
              <Alert variant="destructive" className="mb-4">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {!selectedVM ? (
              <Card className="bg-slate-800/50 border-slate-700 h-[calc(100vh-200px)] flex items-center justify-center">
                <div className="text-center">
                  <Server className="h-16 w-16 text-slate-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-white mb-2">Select a VM to Analyze</h3>
                  <p className="text-slate-400">Choose a virtual machine from the list to begin security analysis</p>
                </div>
              </Card>
            ) : (
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="bg-slate-800/50 border border-slate-700 mb-4">
                  <TabsTrigger value="overview" className="data-[state=active]:bg-blue-600">
                    <Info className="h-4 w-4 mr-2" />
                    Overview
                  </TabsTrigger>
                  <TabsTrigger value="scan" className="data-[state=active]:bg-blue-600">
                    <Eye className="h-4 w-4 mr-2" />
                    Scan Results
                  </TabsTrigger>
                  <TabsTrigger value="report" className="data-[state=active]:bg-blue-600">
                    <FileText className="h-4 w-4 mr-2" />
                    Risk Report
                  </TabsTrigger>
                </TabsList>

                {/* Overview Tab */}
                <TabsContent value="overview">
                  <div className="space-y-4">
                    {/* VM Details Card */}
                    <Card className="bg-slate-800/50 border-slate-700">
                      <CardHeader>
                        <CardTitle className="text-white">{selectedVM.name}</CardTitle>
                        <CardDescription>{selectedVM.id}</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-4 gap-4">
                          <div className="space-y-1">
                            <p className="text-xs text-slate-400">Provider</p>
                            <p className="font-medium text-white">{selectedVM.provider.toUpperCase()}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-xs text-slate-400">Region</p>
                            <p className="font-medium text-white">{selectedVM.region}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-xs text-slate-400">Instance Type</p>
                            <p className="font-medium text-white">{selectedVM.instanceType}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-xs text-slate-400">State</p>
                            <Badge variant={selectedVM.state === 'running' ? 'default' : 'secondary'}>
                              {selectedVM.state}
                            </Badge>
                          </div>
                        </div>

                        <Separator className="my-4 bg-slate-700" />

                        <div className="grid grid-cols-4 gap-4">
                          <div className="space-y-1">
                            <p className="text-xs text-slate-400">Public IP</p>
                            <div className="flex items-center gap-1">
                              {selectedVM.hasPublicIP ? (
                                <>
                                  <Globe className="h-4 w-4 text-orange-400" />
                                  <span className="text-orange-400">Yes</span>
                                </>
                              ) : (
                                <>
                                  <Lock className="h-4 w-4 text-green-400" />
                                  <span className="text-green-400">No</span>
                                </>
                              )}
                            </div>
                          </div>
                          <div className="space-y-1">
                            <p className="text-xs text-slate-400">Disks</p>
                            <p className="font-medium text-white">{selectedVM.diskCount}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-xs text-slate-400">Encrypted Disks</p>
                            <p className="font-medium text-white">
                              {selectedVM.encryptedDisks}/{selectedVM.diskCount}
                            </p>
                          </div>
                        </div>

                        <div className="flex gap-3 mt-6">
                          <Button
                            onClick={() => {
                              scanVM(selectedVM.id);
                              setActiveTab('scan');
                            }}
                            disabled={loading}
                            className="bg-blue-600 hover:bg-blue-700"
                          >
                            {loading ? (
                              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                              <Eye className="h-4 w-4 mr-2" />
                            )}
                            Scan VM
                          </Button>
                          <Button
                            onClick={() => analyzeRisks(selectedVM.id, selectedModel)}
                            disabled={loading}
                            className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700"
                          >
                            {loading ? (
                              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                              <Brain className="h-4 w-4 mr-2" />
                            )}
                            Generate Risk Report
                          </Button>
                        </div>
                      </CardContent>
                    </Card>

                    {/* LLM Status Card */}
                    <Card className="bg-slate-800/50 border-slate-700 border-green-500/30">
                      <CardHeader>
                        <CardTitle className="text-white flex items-center gap-2">
                          <Brain className="h-5 w-5" />
                          Cloud LLM Status
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        {llmStatus ? (
                          <>
                            <div className="grid grid-cols-3 gap-4">
                              <div className="flex items-center gap-2">
                                <div className="h-3 w-3 rounded-full bg-green-500 animate-pulse" />
                                <span className="text-slate-300">
                                  Cloud LLM: Connected
                                </span>
                              </div>
                              <div>
                                <p className="text-xs text-slate-400">Selected Model</p>
                                <p className="font-medium text-white">{selectedModel}</p>
                              </div>
                              <div>
                                <p className="text-xs text-slate-400">Available Models</p>
                                <p className="font-medium text-white">{llmStatus.availableModels?.length || 3}</p>
                              </div>
                            </div>

                            <div className="mt-4 p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                              <h4 className="text-green-400 font-semibold mb-2 flex items-center gap-2">
                                <CheckCircle className="h-4 w-4" />
                                Ready for AI-Powered Risk Analysis
                              </h4>
                              <p className="text-slate-300 text-sm mb-2">
                                <strong>No local installation required!</strong> The LLM runs in the cloud.
                              </p>
                              <p className="text-slate-400 text-xs">
                                Available models: {llmStatus.availableModels?.join(', ') || 'llama-3.3-70b, llama-3.2-3b, mistral-large'}
                              </p>
                            </div>
                          </>
                        ) : (
                          <div className="flex items-center gap-2">
                            <RefreshCw className="h-4 w-4 animate-spin text-slate-400" />
                            <p className="text-slate-400">Connecting to Cloud LLM...</p>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                {/* Scan Results Tab */}
                <TabsContent value="scan">
                  {scanResult ? (
                    <Card className="bg-slate-800/50 border-slate-700">
                      <CardHeader>
                        <CardTitle className="text-white flex items-center gap-2">
                          <Eye className="h-5 w-5" />
                          Misconfigurations Detected
                        </CardTitle>
                        <CardDescription>
                          {scanResult.misconfigurations.length} issues found
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[calc(100vh-380px)]">
                          <div className="space-y-3">
                            {scanResult.misconfigurations.map((misco) => (
                              <div
                                key={misco.id}
                                className="p-4 bg-slate-700/50 rounded-lg border border-slate-600"
                              >
                                <div className="flex items-start justify-between mb-2">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                      <Badge className={getSeverityColor(misco.severity)}>
                                        {misco.severity.toUpperCase()}
                                      </Badge>
                                      <span className="text-sm text-slate-400">{misco.ruleId}</span>
                                    </div>
                                    <h4 className="font-semibold text-white">{misco.title}</h4>
                                  </div>
                                </div>
                                <p className="text-sm text-slate-300 mb-3">{misco.description}</p>
                                <div className="grid grid-cols-2 gap-4 text-sm">
                                  <div>
                                    <p className="text-slate-400">Current:</p>
                                    <p className="text-red-400">{misco.currentValue}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-400">Recommended:</p>
                                    <p className="text-green-400">{misco.recommendedValue}</p>
                                  </div>
                                </div>
                                <Separator className="my-3 bg-slate-600" />
                                <div>
                                  <p className="text-xs text-slate-400 mb-1">Remediation:</p>
                                  <p className="text-sm text-slate-300">{misco.remediation}</p>
                                </div>
                                {misco.cisBenchmark && (
                                  <div className="mt-2">
                                    <Badge variant="outline" className="text-xs">
                                      {misco.cisBenchmark}
                                    </Badge>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  ) : (
                    <Card className="bg-slate-800/50 border-slate-700 h-[calc(100vh-280px)] flex items-center justify-center">
                      <div className="text-center">
                        <Eye className="h-16 w-16 text-slate-600 mx-auto mb-4" />
                        <h3 className="text-xl font-semibold text-white mb-2">No Scan Results</h3>
                        <p className="text-slate-400 mb-4">Run a security scan to see misconfigurations</p>
                        <Button onClick={() => scanVM(selectedVM.id)} disabled={loading}>
                          {loading ? (
                            <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                          ) : (
                            <Eye className="h-4 w-4 mr-2" />
                          )}
                          Scan VM
                        </Button>
                      </div>
                    </Card>
                  )}
                </TabsContent>

                {/* Risk Report Tab */}
                <TabsContent value="report">
                  {securityReport ? (
                    <div className="space-y-4">
                      {/* Summary Card */}
                      <Card className="bg-slate-800/50 border-slate-700">
                        <CardHeader>
                          <CardTitle className="text-white">Security Assessment Summary</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="grid grid-cols-4 gap-6">
                            <div className="text-center">
                              <p className={`text-5xl font-bold ${getRiskScoreColor(securityReport.overallRiskScore)}`}>
                                {securityReport.overallRiskScore}
                              </p>
                              <p className="text-sm text-slate-400 mt-1">Risk Score</p>
                            </div>
                            <div className="text-center">
                              <Badge className={`${getRiskLevelColor(securityReport.riskLevel)} text-lg px-4 py-1`}>
                                {securityReport.riskLevel.toUpperCase()}
                              </Badge>
                              <p className="text-sm text-slate-400 mt-1">Risk Level</p>
                            </div>
                            <div className="text-center">
                              <p className="text-3xl font-bold text-white">{securityReport.complianceScore}%</p>
                              <p className="text-sm text-slate-400 mt-1">Compliance Score</p>
                            </div>
                            <div className="text-center">
                              <p className="text-3xl font-bold text-white">{securityReport.misconfigurations.length}</p>
                              <p className="text-sm text-slate-400 mt-1">Issues Found</p>
                            </div>
                          </div>
                          <Separator className="my-4 bg-slate-700" />
                          <div className="flex items-center justify-between text-sm text-slate-400">
                            <span>Model: {securityReport.analysisMetadata.modelUsed}</span>
                            <span>Duration: {securityReport.analysisMetadata.analysisDuration}ms</span>
                            <span>Rules Applied: {securityReport.analysisMetadata.rulesApplied}</span>
                          </div>
                        </CardContent>
                      </Card>

                      {/* Top 5 Risks */}
                      <Card className="bg-slate-800/50 border-slate-700">
                        <CardHeader>
                          <CardTitle className="text-white flex items-center gap-2">
                            <AlertTriangle className="h-5 w-5 text-red-400" />
                            Top 5 Cyber Risks
                          </CardTitle>
                          <CardDescription>AI-generated risk assessment using {securityReport.analysisMetadata.modelUsed}</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-[calc(100vh-600px)]">
                            <div className="space-y-4">
                              {securityReport.top5Risks.map((risk) => (
                                <div
                                  key={risk.id}
                                  className="p-4 bg-slate-700/50 rounded-lg border border-slate-600"
                                >
                                  <div className="flex items-start justify-between mb-3">
                                    <div className="flex items-center gap-3">
                                      <div className={`flex items-center justify-center w-8 h-8 rounded-full ${getSeverityColor(risk.severity)}`}>
                                        <span className="font-bold text-sm">{risk.rank}</span>
                                      </div>
                                      <div>
                                        <h4 className="font-semibold text-white">{risk.title}</h4>
                                        <div className="flex items-center gap-2 mt-1">
                                          <Badge className={getSeverityColor(risk.severity)}>
                                            {risk.severity.toUpperCase()}
                                          </Badge>
                                          <span className="text-xs text-slate-400">
                                            CVSS: {risk.cvssScore.toFixed(1)}
                                          </span>
                                        </div>
                                      </div>
                                    </div>
                                    <Badge variant="outline" className="text-xs">
                                      {risk.remediationPriority}
                                    </Badge>
                                  </div>
                                  
                                  <p className="text-sm text-slate-300 mb-3">{risk.description}</p>
                                  
                                  <div className="grid grid-cols-2 gap-4 mb-3">
                                    <div>
                                      <p className="text-xs text-slate-400 mb-1">Attack Vector</p>
                                      <p className="text-sm text-red-300">{risk.attackVector}</p>
                                    </div>
                                    <div>
                                      <p className="text-xs text-slate-400 mb-1">Business Impact</p>
                                      <p className="text-sm text-orange-300">{risk.businessImpact}</p>
                                    </div>
                                  </div>
                                  
                                  <Separator className="my-3 bg-slate-600" />
                                  
                                  <div>
                                    <p className="text-xs text-slate-400 mb-2">Remediation Steps:</p>
                                    <ol className="list-decimal list-inside space-y-1">
                                      {risk.remediationSteps.map((step, i) => (
                                        <li key={i} className="text-sm text-green-300">{step}</li>
                                      ))}
                                    </ol>
                                  </div>
                                  
                                  <div className="flex items-center gap-2 mt-3 text-xs text-slate-400">
                                    <Clock className="h-3 w-3" />
                                    <span>Est. remediation: {risk.estimatedRemediationTime}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        </CardContent>
                      </Card>

                      {/* Recommendations */}
                      <Card className="bg-slate-800/50 border-slate-700">
                        <CardHeader>
                          <CardTitle className="text-white flex items-center gap-2">
                            <Zap className="h-5 w-5 text-yellow-400" />
                            Recommendations
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-2">
                            {securityReport.recommendations.map((rec, i) => (
                              <li key={i} className="flex items-start gap-2 text-slate-300">
                                <ChevronRight className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                                <span>{rec}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </div>
                  ) : (
                    <Card className="bg-slate-800/50 border-slate-700 h-[calc(100vh-280px)] flex items-center justify-center">
                      <div className="text-center">
                        <Brain className="h-16 w-16 text-slate-600 mx-auto mb-4" />
                        <h3 className="text-xl font-semibold text-white mb-2">No Risk Report</h3>
                        <p className="text-slate-400 mb-4">Generate a report to see AI-powered risk analysis</p>
                        <Button
                          onClick={() => analyzeRisks(selectedVM.id, selectedModel)}
                          disabled={loading}
                          className="bg-gradient-to-r from-purple-600 to-blue-600"
                        >
                          {loading ? (
                            <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                          ) : (
                            <Brain className="h-4 w-4 mr-2" />
                          )}
                          Generate Risk Report
                        </Button>
                      </div>
                    </Card>
                  )}
                </TabsContent>
              </Tabs>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
