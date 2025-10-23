import React, { useState } from 'react';
import { Shield, AlertTriangle, Brain, BarChart3, FileText, Zap, RefreshCw, TrendingUp, Cpu, Network } from 'lucide-react';

const ThreatIntelPipeline = () => {
  const [logEntry, setLogEntry] = useState('Oct 21 13:14:52 sshd[2310]: Failed password for invalid user admin from 192.168.0.101 port 22');
  const [analysis, setAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [llmProvider, setLlmProvider] = useState('openai');
  const [apiKey, setApiKey] = useState('');
  const [showApiInput, setShowApiInput] = useState(false);
  const [useMockLLM, setUseMockLLM] = useState(true);

  const sampleLogs = [
    `Oct 21 13:14:52 sshd[2310]: Failed password for invalid user admin from 192.168.0.101 port 22
Oct 21 13:15:05 sshd[2310]: Failed password for invalid user root from 192.168.0.102 port 22
Oct 21 13:15:18 sshd[2310]: Failed password for invalid user test from 192.168.0.103 port 22`,
    `Oct 22 09:05:11 postfix/smtpd[1520]: NOQUEUE: reject: RCPT from unknown[203.0.113.45]: 554 5.7.1 <user@example.com>: Recipient address rejected: Spam detected
Oct 22 09:05:12 postfix/smtpd[1520]: warning: header From user@malicious.com suspicious
Oct 22 09:05:13 amavis[860]: (860-01) Blocked SPAM {mail from=user@malicious.com}`,
    `Oct 22 11:45:23 proxy[4042]: DENY TCP 192.168.0.150:51423 -> 198.51.100.25:443 URL http://malicious-site.com/malware.exe
Oct 22 11:45:23 proxy[4042]: Action=Blocked Policy=Malware_Download`,
    `Oct 22 12:03:12 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:68:22:33 SRC=203.0.113.55 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO=TCP SPT=12345 DPT=80 SYN
Oct 22 12:03:12 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:68:22:34 SRC=203.0.113.56 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=53 ID=54322 DF PROTO=TCP SPT=12346 DPT=80 SYN
Oct 22 12:03:12 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:68:22:35 SRC=203.0.113.57 DST=192.168.0.10 LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID=54323 DF PROTO=TCP SPT=12347 DPT=80 SYN`,
    `Oct 22 14:12:45 winlogbeat: User JohnDoe attempted to execute C:\\Users\\JohnDoe\\Downloads\\unknown.exe
Oct 22 14:12:45 winlogbeat: Antivirus blocked execution of unknown.exe
Oct 22 14:12:46 winlogbeat: User JohnDoe attempted to copy C:\\SensitiveDocs\\finance.xlsx to USB`
  ];

  const generateMockLLMResponse = async (logData) => {
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    const lower = logData.toLowerCase();
    
    if (lower.includes('failed password') || lower.includes('sshd')) {
      return {
        summary: "This log indicates a coordinated SSH brute-force attack. Multiple authentication failures from different IP addresses targeting common administrative usernames (admin, root, test) within seconds suggest automated credential stuffing using compromised credential lists or dictionary attacks.",
        technicalAnalysis: "The attacker is systematically probing SSH service (port 22) with common default usernames. The rapid succession and multiple source IPs indicate either a distributed botnet or compromised IoT devices being used as attack infrastructure.",
        attackNarrative: "At 13:14:52, an attacker initiated a brute-force campaign against the SSH service. Using automated tools, they attempted authentication with 'admin' from 192.168.0.101, followed immediately by attempts from .102 and .103 with 'root' and 'test' usernames. This pattern indicates reconnaissance and exploitation phases of the cyber kill chain.",
        tacticsAndTechniques: "MITRE ATT&CK T1110.001 - Brute Force: Password Guessing. The adversary is attempting to gain initial access through credential brute-forcing, a common technique used by both opportunistic attackers and sophisticated threat actors.",
        businessImpact: "If successful, attackers would gain unauthorized shell access to critical systems, potentially leading to data theft, ransomware deployment, or lateral movement across the network. Estimated risk: HIGH",
        recommendations: [
          "Implement fail2ban or similar rate-limiting solutions",
          "Enable multi-factor authentication (MFA) for SSH access",
          "Block source IP ranges at firewall level",
          "Deploy honeypot SSH services to track attacker behavior"
        ]
      };
    } else if (lower.includes('spam') || lower.includes('malicious.com')) {
      return {
        summary: "Email security systems detected and blocked a phishing campaign. The email originated from a suspicious domain (malicious.com) and triggered multiple security filters including spam detection and header analysis.",
        technicalAnalysis: "The mail server rejected the SMTP connection due to spam detection rules. Header analysis revealed sender address spoofing, a common technique in phishing campaigns to impersonate legitimate organizations.",
        attackNarrative: "At 09:05:11, the mail gateway received an email from user@malicious.com targeting user@example.com. The system immediately flagged the sender domain as suspicious and blocked the message before delivery. This proactive defense prevented potential credential harvesting or malware delivery.",
        tacticsAndTechniques: "MITRE ATT&CK T1566.002 - Phishing: Spearphishing Link. Attackers use email as an initial access vector, often including malicious links or attachments designed to compromise recipients.",
        businessImpact: "Blocked phishing attempts prevent credential compromise, financial fraud, and malware infections. This incident demonstrates effective email security controls. Estimated risk: MEDIUM (successfully blocked)",
        recommendations: [
          "Add malicious.com to email blocklist",
          "Conduct phishing awareness training for staff",
          "Enable DMARC, SPF, and DKIM validation",
          "Deploy advanced email threat protection (ATP)"
        ]
      };
    } else if (lower.includes('malware') || lower.includes('.exe')) {
      return {
        summary: "Web proxy successfully intercepted and blocked a malware download attempt. An internal host (192.168.0.150) attempted to download an executable file from a known malicious domain.",
        technicalAnalysis: "The proxy's threat intelligence integration identified malicious-site.com as a known malware distribution point. The Policy=Malware_Download rule prevented the executable from reaching the endpoint, stopping the infection chain.",
        attackNarrative: "At 11:45:23, an endpoint user attempted to access malicious-site.com and download malware.exe. This could indicate a drive-by download attack where the user was redirected through compromised websites, or social engineering leading the user to manually download malicious software. The web proxy's real-time threat intelligence prevented system compromise.",
        tacticsAndTechniques: "MITRE ATT&CK T1204.002 - User Execution: Malicious File. Attackers rely on users executing malicious payloads, often disguised as legitimate software or documents.",
        businessImpact: "Prevented malware infection that could lead to ransomware, data theft, or botnet enrollment. The user may be compromised or targeted and requires security awareness training. Estimated risk: CRITICAL (attempt blocked)",
        recommendations: [
          "Investigate endpoint 192.168.0.150 for compromise",
          "Block malicious-site.com at DNS and firewall levels",
          "Submit malware.exe to VirusTotal for analysis",
          "Provide security training to affected user"
        ]
      };
    } else if (lower.includes('syn') || lower.includes('ufw block')) {
      return {
        summary: "A large-scale SYN flood DDoS attack is targeting the web server. Multiple source IPs are sending high volumes of TCP SYN packets to overwhelm the server and cause service disruption.",
        technicalAnalysis: "The firewall logged numerous blocked SYN packets from sequential IP addresses (203.0.113.55-57) targeting port 80. The incrementing IP addresses and identical packet characteristics suggest a coordinated botnet attack.",
        attackNarrative: "At 12:03:12, the server came under DDoS attack with hundreds of SYN packets flooding the network interface. The attacker aims to exhaust server resources by filling the TCP connection table, preventing legitimate users from accessing services. The firewall is actively blocking malicious traffic but continued assault may degrade performance.",
        tacticsAndTechniques: "MITRE ATT&CK T1498.001 - Network Denial of Service: Direct Network Flood. Attackers generate massive traffic volumes to exhaust network bandwidth or server resources.",
        businessImpact: "Active DDoS attack threatens service availability and business operations. May impact revenue, customer satisfaction, and reputation. Requires immediate mitigation. Estimated risk: CRITICAL (ongoing attack)",
        recommendations: [
          "Enable SYN cookies on affected servers",
          "Deploy DDoS mitigation service (Cloudflare, Akamai)",
          "Contact ISP for upstream traffic filtering",
          "Implement rate limiting and connection throttling"
        ]
      };
    } else if (lower.includes('usb') || lower.includes('execute')) {
      return {
        summary: "Detected a multi-stage insider threat: attempted malware execution followed by sensitive data exfiltration to USB device. User JohnDoe's actions indicate either compromised credentials or malicious insider activity.",
        technicalAnalysis: "Sequence analysis shows: (1) Attempted execution of unknown.exe from Downloads folder, blocked by AV; (2) Immediately followed by attempt to copy finance.xlsx to external USB. This pattern is consistent with data theft operations where attackers first attempt to install tools, then exfiltrate data.",
        attackNarrative: "At 14:12:45, user JohnDoe attempted to run an unidentified executable, which antivirus blocked as malicious. Seconds later, the same user tried copying sensitive financial documents to an external USB drive. This behavioral sequence strongly suggests either account compromise by external attackers or insider threat with intent to steal proprietary data.",
        tacticsAndTechniques: "MITRE ATT&CK T1204.002 (User Execution: Malicious File) + T1052.001 (Exfiltration Over Physical Medium). Attacker combined malware deployment with data exfiltration, indicating sophisticated multi-stage attack.",
        businessImpact: "HIGH SEVERITY: Potential data breach involving financial records. Requires immediate incident response, user interview, forensic analysis, and regulatory compliance assessment. Estimated risk: CRITICAL (data exposure)",
        recommendations: [
          "Immediately disable JohnDoe's account and network access",
          "Isolate affected endpoint for forensic analysis",
          "Review all file access logs for data exposure assessment",
          "Implement USB device control policies",
          "Conduct HR investigation and potential law enforcement notification"
        ]
      };
    }
    
    return {
      summary: "Security event detected requiring investigation. The log shows suspicious activity patterns that warrant further analysis.",
      technicalAnalysis: "Log analysis indicates potential security concern. Additional context and correlation with other security events needed for complete assessment.",
      attackNarrative: "Security monitoring systems flagged unusual activity. Investigation required to determine if this represents legitimate behavior or malicious intent.",
      tacticsAndTechniques: "Requires correlation with MITRE ATT&CK framework and threat intelligence for full tactics analysis.",
      businessImpact: "Risk level uncertain pending investigation. Recommend enhanced monitoring and security review. Estimated risk: MEDIUM (requires analysis)",
      recommendations: [
        "Correlate with SIEM and threat intelligence feeds",
        "Enable enhanced logging for affected systems",
        "Conduct security review of related events",
        "Document findings for compliance audit trail"
      ]
    };
  };

  const callRealLLM = async (logData) => {
    const systemPrompt = `You are an elite cybersecurity threat analyst with expertise in SIEM, incident response, and threat intelligence. Analyze security logs and provide detailed threat assessments.

Return your analysis in this JSON format:
{
  "summary": "Brief overview of the security event",
  "technicalAnalysis": "Detailed technical breakdown of the attack",
  "attackNarrative": "Timeline and story of what happened",
  "tacticsAndTechniques": "MITRE ATT&CK mapping and techniques used",
  "businessImpact": "Risk assessment and business implications",
  "recommendations": ["action1", "action2", "action3"]
}`;

    const userPrompt = `Analyze this security log and provide comprehensive threat intelligence:

LOG DATA:
${logData}

Provide expert analysis covering:
1. What type of attack is this?
2. Technical indicators and patterns
3. Attack timeline and narrative
4. MITRE ATT&CK techniques
5. Business risk and impact
6. Actionable recommendations`;

    try {
      let response;
      
      if (llmProvider === 'openai') {
        response = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body: JSON.stringify({
            model: 'gpt-4',
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt }
            ],
            temperature: 0.7,
            max_tokens: 1500
          })
        });
      } else if (llmProvider === 'anthropic') {
        response = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model: 'claude-3-sonnet-20240229',
            max_tokens: 1500,
            messages: [
              { role: 'user', content: `${systemPrompt}\n\n${userPrompt}` }
            ]
          })
        });
      }

      const data = await response.json();
      let content;
      
      if (llmProvider === 'openai') {
        content = data.choices[0].message.content;
      } else if (llmProvider === 'anthropic') {
        content = data.content[0].text;
      }
      
      try {
        return JSON.parse(content);
      } catch {
        return {
          summary: content.substring(0, 300),
          technicalAnalysis: "See full response",
          attackNarrative: "Detailed in summary",
          tacticsAndTechniques: "Multiple techniques identified",
          businessImpact: "Requires assessment",
          recommendations: ["Review full LLM response", "Conduct further investigation"]
        };
      }
    } catch (error) {
      console.error('LLM API Error:', error);
      throw new Error('Failed to connect to LLM service. Please check your API key and network connection.');
    }
  };

  const analyzeLogPatterns = (log) => {
    const lower = log.toLowerCase();
    const lines = log.split('\n').filter(l => l.trim());
    
    const patterns = {
      multipleSources: /from\s+(\d+\.\d+\.\d+\.\d+)/gi,
      repeatedAction: /(failed|blocked|denied|reject)/gi,
      timeWindow: /\d{2}:\d{2}:\d{2}/g,
      suspiciousFiles: /\.(exe|bat|ps1|vbs|js|jar)/gi,
      sensitiveData: /(finance|password|credential|ssn|credit|confidential|sensitive)/gi
    };

    return {
      isMultiLine: lines.length > 1,
      lineCount: lines.length,
      uniqueIPs: [...new Set(log.match(patterns.multipleSources) || [])].length,
      failureCount: (log.match(patterns.repeatedAction) || []).length,
      hasSuspiciousFiles: patterns.suspiciousFiles.test(log),
      hasSensitiveData: patterns.sensitiveData.test(log),
      timestamps: log.match(patterns.timeWindow) || []
    };
  };

  const extractIOCs = (log) => {
    const iocs = {
      ips: [],
      domains: [],
      users: [],
      ports: [],
      files: [],
      emails: []
    };

    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const domainRegex = /(?:https?:\/\/)?([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)/g;
    const userRegex = /(?:user|from)\s+(\w+)/gi;
    const portRegex = /(?:port|dpt|spt)[=:\s]+(\d+)/gi;
    const fileRegex = /([A-Za-z]:\\[^\s]+|\/[^\s]+\.(?:exe|bat|ps1|vbs|js|jar|xlsx|docx|pdf))/gi;
    const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;

    iocs.ips = [...new Set(log.match(ipRegex) || [])];
    
    const domainMatches = log.match(domainRegex) || [];
    iocs.domains = [...new Set(domainMatches.map(d => d.replace(/^https?:\/\//, '')))];
    
    let userMatch;
    const userRegexNew = /(?:user|from)\s+(\w+)/gi;
    while ((userMatch = userRegexNew.exec(log)) !== null) {
      if (!iocs.users.includes(userMatch[1])) {
        iocs.users.push(userMatch[1]);
      }
    }
    
    let portMatch;
    const portRegexNew = /(?:port|dpt|spt)[=:\s]+(\d+)/gi;
    while ((portMatch = portRegexNew.exec(log)) !== null) {
      if (!iocs.ports.includes(portMatch[1])) {
        iocs.ports.push(portMatch[1]);
      }
    }

    iocs.files = [...new Set(log.match(fileRegex) || [])];
    iocs.emails = [...new Set(log.match(emailRegex) || [])];

    return iocs;
  };

  const quickClassify = (log) => {
    const lower = log.toLowerCase();
    if (lower.includes('failed password') || lower.includes('sshd')) return 'brute-force';
    if (lower.includes('spam') || lower.includes('phishing')) return 'phishing';
    if (lower.includes('malware') || lower.includes('.exe')) return 'malware-download';
    if (lower.includes('syn') || lower.includes('ufw block')) return 'ddos-synflood';
    if (lower.includes('usb') || lower.includes('sensitive')) return 'data-exfiltration';
    return 'suspicious-activity';
  };

  const analyzeThreat = async () => {
    setIsAnalyzing(true);
    setAnalysis(null);

    try {
      const patterns = analyzeLogPatterns(logEntry);
      const iocs = extractIOCs(logEntry);
      const quickCategory = quickClassify(logEntry);

      let llmResponse;
      if (useMockLLM) {
        llmResponse = await generateMockLLMResponse(logEntry);
      } else {
        llmResponse = await callRealLLM(logEntry);
      }

      setAnalysis({
        llmAnalysis: llmResponse,
        patterns,
        iocs,
        quickCategory,
        timestamp: new Date().toISOString(),
        usedMockLLM: useMockLLM
      });
    } catch (error) {
      alert(`Analysis failed: ${error.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getSeverityColor = (category) => {
    const colors = {
      'brute-force': 'bg-orange-500',
      'phishing': 'bg-yellow-500',
      'malware-download': 'bg-red-600',
      'ddos-synflood': 'bg-red-600',
      'data-exfiltration': 'bg-red-500',
      'suspicious-activity': 'bg-yellow-600'
    };
    return colors[category] || 'bg-slate-500';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8 text-center">
          <div className="flex items-center justify-center gap-3 mb-3">
            <Shield className="w-10 h-10 text-cyan-400" />
            <h1 className="text-4xl font-bold text-white">LLM-Powered Threat Intelligence</h1>
          </div>
          <p className="text-slate-300 text-lg">Rapid AI Security Analysis Pipeline</p>
        </div>

        <div className="bg-gradient-to-r from-purple-900/40 to-blue-900/40 rounded-xl border border-purple-500/30 p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-purple-400" />
              <h2 className="text-xl font-semibold text-white">LLM Configuration</h2>
            </div>
            <button
              onClick={() => setShowApiInput(!showApiInput)}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded-lg transition-colors"
            >
              {showApiInput ? 'Hide' : 'Configure'} API
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="text-slate-300 text-sm mb-2 block">LLM Provider</label>
              <select
                value={llmProvider}
                onChange={(e) => setLlmProvider(e.target.value)}
                className="w-full bg-slate-800 text-slate-200 border border-slate-600 rounded-lg p-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
              >
                <option value="openai">OpenAI GPT-4</option>
                <option value="anthropic">Anthropic Claude</option>
              </select>
            </div>
            <div className="flex items-end">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useMockLLM}
                  onChange={(e) => setUseMockLLM(e.target.checked)}
                  className="w-4 h-4"
                />
                <span className="text-slate-300 text-sm">Use Mock LLM (Demo Mode)</span>
              </label>
            </div>
            <div className="flex items-end">
              <div className={`px-3 py-2 rounded-lg text-sm ${useMockLLM ? 'bg-green-500/20 text-green-300' : 'bg-blue-500/20 text-blue-300'}`}>
                {useMockLLM ? '🤖 Demo Mode Active' : '🚀 Live API Mode'}
              </div>
            </div>
          </div>

          {showApiInput && !useMockLLM && (
            <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
              <label className="text-slate-300 text-sm mb-2 block">API Key</label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={llmProvider === 'anthropic' ? 'sk-ant-xxx' : 'sk-xxx'}
                className="w-full bg-slate-900 text-slate-200 border border-slate-600 rounded-lg p-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
              <p className="text-slate-400 text-xs mt-2">
                💡 Get your {llmProvider === 'anthropic' ? 'Anthropic' : 'OpenAI'} API key at: {llmProvider === 'anthropic' ? 'console.anthropic.com' : 'platform.openai.com'}
              </p>
            </div>
          )}
        </div>

        <div className="bg-slate-800 rounded-xl shadow-2xl border border-slate-700 p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h2 className="text-xl font-semibold text-white">Security Log Input</h2>
          </div>
          
          <textarea
            value={logEntry}
            onChange={(e) => setLogEntry(e.target.value)}
            className="w-full bg-slate-900 text-slate-200 border border-slate-600 rounded-lg p-4 font-mono text-sm mb-4 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            rows={6}
            placeholder="Paste security log entry here..."
          />
          
          <div className="flex flex-wrap gap-2 mb-4">
            <span className="text-slate-400 text-sm">Sample scenarios:</span>
            {['SSH Brute-force', 'Phishing Email', 'Malware Download', 'DDoS/SYN Flood', 'Data Exfiltration'].map((label, idx) => (
              <button
                key={idx}
                onClick={() => setLogEntry(sampleLogs[idx])}
                className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs rounded-full transition-colors"
              >
                {label}
              </button>
            ))}
          </div>

          <button
            onClick={analyzeThreat}
            disabled={isAnalyzing || !logEntry || (!useMockLLM && !apiKey)}
            className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 disabled:from-slate-600 disabled:to-slate-700 text-white font-semibold py-3 rounded-lg transition-all flex items-center justify-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <RefreshCw className="w-5 h-5 animate-spin" />
                LLM Analyzing Security Threat...
              </>
            ) : (
              <>
                <Brain className="w-5 h-5" />
                Run LLM-Powered Analysis
              </>
            )}
          </button>
        </div>

        {analysis && (
          <div className="space-y-6">
            <div className="bg-gradient-to-br from-purple-900/30 to-blue-900/30 rounded-xl border border-purple-500/30 p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Brain className="w-6 h-6 text-purple-400" />
                  <h2 className="text-2xl font-bold text-white">LLM Threat Analysis</h2>
                </div>
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-purple-400" />
                  <span className="text-purple-300 text-sm">
                    {analysis.usedMockLLM ? 'Mock LLM' : llmProvider.toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="bg-slate-900/50 rounded-lg p-5 mb-4 border border-purple-500/20">
                <h3 className="text-purple-300 font-semibold mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5" />
                  Executive Summary
                </h3>
                <p className="text-slate-200 leading-relaxed">{analysis.llmAnalysis.summary}</p>
              </div>

              <div className="bg-slate-900/50 rounded-lg p-5 mb-4 border border-blue-500/20">
                <h3 className="text-blue-300 font-semibold mb-3">🔬 Technical Analysis</h3>
                <p className="text-slate-200 leading-relaxed">{analysis.llmAnalysis.technicalAnalysis}</p>
              </div>

              <div className="bg-slate-900/50 rounded-lg p-5 mb-4 border border-cyan-500/20">
                <h3 className="text-cyan-300 font-semibold mb-3">📖 Attack Narrative</h3>
                <p className="text-slate-200 leading-relaxed">{analysis.llmAnalysis.attackNarrative}</p>
              </div>

              <div className="bg-slate-900/50 rounded-lg p-5 mb-4 border border-green-500/20">
                <h3 className="text-green-300 font-semibold mb-3">🎯 Tactics & Techniques (MITRE ATT&CK)</h3>
                <p className="text-slate-200 leading-relaxed">{analysis.llmAnalysis.tacticsAndTechniques}</p>
              </div>

              <div className="bg-slate-900/50 rounded-lg p-5 mb-4 border border-red-500/20">
                <h3 className="text-red-300 font-semibold mb-3">💼 Business Impact Assessment</h3>
                <p className="text-slate-200 leading-relaxed">{analysis.llmAnalysis.businessImpact}</p>
              </div>

              <div className="bg-slate-900/50 rounded-lg p-5 border border-yellow-500/20">
                <h3 className="text-yellow-300 font-semibold mb-3">✅ Recommended Actions</h3>
                <ul className="space-y-2">
                  {analysis.llmAnalysis.recommendations?.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-slate-200">
                      <span className="text-cyan-400 mt-1">▸</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="bg-slate-800 rounded-xl shadow-2xl border border-slate-700 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Zap className="w-5 h-5 text-yellow-400" />
                <h2 className="text-xl font-semibold text-white">Quick Classification</h2>
              </div>
              <div className={`${getSeverityColor(analysis.quickCategory)} text-white px-6 py-3 rounded-lg font-bold uppercase text-lg inline-block`}>
                {analysis.quickCategory.replace(/-/g, ' ')}
              </div>
            </div>

            <div className="bg-slate-800 rounded-xl shadow-2xl border border-slate-700 p-6">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp className="w-5 h-5 text-green-400" />
                <h2 className="text-xl font-semibold text-white">Pattern Analysis Metrics</h2>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-900 rounded-lg p-4">
                  <div className="text-slate-400 text-xs mb-1">Log Entries</div>
                  <div className="text-white text-2xl font-bold">{analysis.patterns.lineCount}</div>
                </div>
                <div className="bg-slate-900 rounded-lg p-4">
                  <div className="text-slate-400 text-xs mb-1">Unique IPs</div>
                  <div className="text-white text-2xl font-bold">{analysis.patterns.uniqueIPs}</div>
                </div>
                <div className="bg-slate-900 rounded-lg p-4">
                  <div className="text-slate-400 text-xs mb-1">Failures/Blocks</div>
                  <div className="text-white text-2xl font-bold">{analysis.patterns.failureCount}</div>
                </div>
                <div className="bg-slate-900 rounded-lg p-4">
                  <div className="text-slate-400 text-xs mb-1">Suspicious Files</div>
                  <div className="text-white text-2xl font-bold">{analysis.patterns.hasSuspiciousFiles ? 'YES' : 'NO'}</div>
                </div>
              </div>
            </div>

            <div className="bg-slate-800 rounded-xl shadow-2xl border border-slate-700 p-6">
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 className="w-5 h-5 text-cyan-400" />
                <h2 className="text-xl font-semibold text-white">Indicators of Compromise (IOCs)</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {analysis.iocs.ips.length > 0 && (
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h3 className="text-red-400 font-semibold mb-2 flex items-center gap-2">
                      🌐 IP Addresses ({analysis.iocs.ips.length})
                    </h3>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {analysis.iocs.ips.map((ip, idx) => (
                        <div key={idx} className="text-slate-300 font-mono text-sm bg-slate-800 px-3 py-1 rounded">
                          {ip}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.iocs.domains.length > 0 && (
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h3 className="text-orange-400 font-semibold mb-2 flex items-center gap-2">
                      🔗 Domains ({analysis.iocs.domains.length})
                    </h3>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {analysis.iocs.domains.map((domain, idx) => (
                        <div key={idx} className="text-slate-300 font-mono text-sm bg-slate-800 px-3 py-1 rounded">
                          {domain}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.iocs.users.length > 0 && (
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h3 className="text-yellow-400 font-semibold mb-2 flex items-center gap-2">
                      👤 Usernames ({analysis.iocs.users.length})
                    </h3>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {analysis.iocs.users.map((user, idx) => (
                        <div key={idx} className="text-slate-300 font-mono text-sm bg-slate-800 px-3 py-1 rounded">
                          {user}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.iocs.ports.length > 0 && (
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h3 className="text-cyan-400 font-semibold mb-2 flex items-center gap-2">
                      🔌 Ports ({analysis.iocs.ports.length})
                    </h3>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {analysis.iocs.ports.map((port, idx) => (
                        <div key={idx} className="text-slate-300 font-mono text-sm bg-slate-800 px-3 py-1 rounded">
                          {port}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.iocs.files.length > 0 && (
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h3 className="text-purple-400 font-semibold mb-2 flex items-center gap-2">
                      📁 Suspicious Files ({analysis.iocs.files.length})
                    </h3>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {analysis.iocs.files.map((file, idx) => (
                        <div key={idx} className="text-slate-300 font-mono text-xs bg-slate-800 px-3 py-1 rounded break-all">
                          {file}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.iocs.emails.length > 0 && (
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h3 className="text-pink-400 font-semibold mb-2 flex items-center gap-2">
                      📧 Email Addresses ({analysis.iocs.emails.length})
                    </h3>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {analysis.iocs.emails.map((email, idx) => (
                        <div key={idx} className="text-slate-300 font-mono text-sm bg-slate-800 px-3 py-1 rounded">
                          {email}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-slate-800 rounded-xl shadow-2xl border border-slate-700 p-4">
              <div className="text-slate-400 text-xs">
                Analysis completed at {new Date(analysis.timestamp).toLocaleString()} • Powered by {analysis.usedMockLLM ? 'Mock' : llmProvider.toUpperCase()} LLM
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatIntelPipeline;
