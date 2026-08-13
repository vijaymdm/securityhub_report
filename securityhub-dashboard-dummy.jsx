import React, { useState, useMemo } from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Download, ChevronDown, Activity, Clock } from 'lucide-react';

// ============================================================
// POC DEMO — title_dummy
// Static mock data only. No API calls, no AWS connection.
// Purpose: stakeholder approval / walkthrough demo.
// For production use, see securityhub-dashboard.jsx.
// ============================================================

const DASHBOARD_VERSION = '1.3.0-demo';

// ---- Dummy accounts ----
const DUMMY_ACCOUNTS = [
  { id: 'all',          name: 'All Accounts',            accountId: '' },
  { id: '111122223333', name: 'Prod - Core Services',    accountId: '111122223333' },
  { id: '222233334444', name: 'Prod - Data Platform',    accountId: '222233334444' },
  { id: '333344445555', name: 'NonProd - Sandbox',       accountId: '333344445555' },
  { id: '444455556666', name: 'Shared - Networking',     accountId: '444455556666' },
  { id: '555566667777', name: 'Prod - Analytics',        accountId: '555566667777' },
  { id: '666677778888', name: 'Shared - Security',       accountId: '666677778888' },
];

// ---- Dummy summaries ----
const DUMMY_SUMMARIES = {
  all:            { accountId: 'all',          critical: 14, high: 38, medium: 97, low: 214, score: 73, passedControls: 198, totalEnabledControls: 274, lastScan: '2026-08-12 03:14 UTC' },
  '111122223333': { accountId: '111122223333', critical:  5, high: 12, medium: 28, low:  56, score: 71, passedControls:  48, totalEnabledControls:  68, lastScan: '2026-08-12 03:14 UTC' },
  '222233334444': { accountId: '222233334444', critical:  2, high:  6, medium: 18, low:  39, score: 81, passedControls:  44, totalEnabledControls:  55, lastScan: '2026-08-12 03:14 UTC' },
  '333344445555': { accountId: '333344445555', critical:  3, high:  9, medium: 22, low:  48, score: 68, passedControls:  36, totalEnabledControls:  53, lastScan: '2026-08-12 03:14 UTC' },
  '444455556666': { accountId: '444455556666', critical:  1, high:  4, medium: 12, low:  28, score: 86, passedControls:  40, totalEnabledControls:  47, lastScan: '2026-08-12 03:14 UTC' },
  '555566667777': { accountId: '555566667777', critical:  2, high:  5, medium: 11, low:  26, score: 78, passedControls:  21, totalEnabledControls:  27, lastScan: '2026-08-12 03:14 UTC' },
  '666677778888': { accountId: '666677778888', critical:  1, high:  2, medium:  6, low:  17, score: 91, passedControls:   9, totalEnabledControls:  10, lastScan: '2026-08-12 03:14 UTC' },
};

// ---- Dummy top controls per account ----
const DUMMY_CONTROLS = {
  all: [
    { id: 'S3.8',        title: 'S3 buckets should block public access',                      severity: 'CRITICAL', count: 14 },
    { id: 'IAM.6',       title: 'Hardware MFA should be enabled for root user',               severity: 'CRITICAL', count:  9 },
    { id: 'EC2.19',      title: 'Security groups should not allow unrestricted access',       severity: 'HIGH',     count: 22 },
    { id: 'CloudTrail.1',title: 'CloudTrail should be enabled with at least one multi-region trail', severity: 'HIGH', count: 11 },
    { id: 'RDS.3',       title: 'RDS DB instances should have encryption at-rest enabled',    severity: 'MEDIUM',   count: 38 },
  ],
  '111122223333': [
    { id: 'S3.8',        title: 'S3 buckets should block public access',                      severity: 'CRITICAL', count:  5 },
    { id: 'IAM.6',       title: 'Hardware MFA should be enabled for root user',               severity: 'CRITICAL', count:  3 },
    { id: 'EC2.19',      title: 'Security groups should not allow unrestricted access',       severity: 'HIGH',     count:  8 },
    { id: 'RDS.3',       title: 'RDS DB instances should have encryption at-rest enabled',    severity: 'MEDIUM',   count: 12 },
    { id: 'Lambda.1',    title: 'Lambda function policies should prohibit public access',     severity: 'HIGH',     count:  4 },
  ],
  '222233334444': [
    { id: 'S3.8',        title: 'S3 buckets should block public access',                      severity: 'CRITICAL', count:  2 },
    { id: 'EC2.19',      title: 'Security groups should not allow unrestricted access',       severity: 'HIGH',     count:  4 },
    { id: 'RDS.3',       title: 'RDS DB instances should have encryption at-rest enabled',    severity: 'MEDIUM',   count:  9 },
    { id: 'Kinesis.1',   title: 'Kinesis streams should be encrypted at rest',               severity: 'MEDIUM',   count:  5 },
    { id: 'CloudTrail.1',title: 'CloudTrail should be enabled with at least one multi-region trail', severity: 'HIGH', count:  2 },
  ],
  '333344445555': [
    { id: 'IAM.6',       title: 'Hardware MFA should be enabled for root user',               severity: 'CRITICAL', count:  3 },
    { id: 'EC2.19',      title: 'Security groups should not allow unrestricted access',       severity: 'HIGH',     count:  6 },
    { id: 'S3.8',        title: 'S3 buckets should block public access',                      severity: 'CRITICAL', count:  2 },
    { id: 'CloudTrail.1',title: 'CloudTrail should be enabled with at least one multi-region trail', severity: 'HIGH', count:  3 },
    { id: 'RDS.13',      title: 'RDS automatic minor version upgrade should be enabled',     severity: 'MEDIUM',   count:  8 },
  ],
  '444455556666': [
    { id: 'EC2.19',      title: 'Security groups should not allow unrestricted access',       severity: 'HIGH',     count:  3 },
    { id: 'VPC.4',       title: 'VPC should have a flow log configured',                     severity: 'MEDIUM',   count:  4 },
    { id: 'EC2.2',       title: 'VPC default security groups should not allow inbound traffic',severity:'MEDIUM',  count:  3 },
    { id: 'EC2.21',      title: 'Network ACLs should not allow ingress on port 22 or 3389',  severity: 'HIGH',     count:  1 },
    { id: 'CloudTrail.1',title: 'CloudTrail should be enabled with at least one multi-region trail', severity: 'HIGH', count:  0 },
  ],
  '555566667777': [
    { id: 'S3.8',        title: 'S3 buckets should block public access',                      severity: 'CRITICAL', count:  2 },
    { id: 'Glue.1',      title: 'AWS Glue jobs should be encrypted',                          severity: 'MEDIUM',   count:  4 },
    { id: 'EMR.1',       title: 'EMR cluster master nodes should not have public IP addresses',severity: 'HIGH',    count:  2 },
    { id: 'Athena.1',    title: 'Athena workgroups should be encrypted at rest',             severity: 'MEDIUM',   count:  3 },
    { id: 'RDS.3',       title: 'RDS DB instances should have encryption at-rest enabled',    severity: 'MEDIUM',   count:  4 },
  ],
  '666677778888': [
    { id: 'IAM.6',       title: 'Hardware MFA should be enabled for root user',               severity: 'CRITICAL', count:  1 },
    { id: 'SecurityHub.1',title:'Security Hub should be enabled for an AWS account',          severity: 'MEDIUM',   count:  2 },
    { id: 'Config.1',    title: 'AWS Config should be enabled',                               severity: 'MEDIUM',   count:  2 },
    { id: 'IAM.21',      title: 'IAM customer managed policies should not allow wildcard actions', severity: 'HIGH', count:  1 },
    { id: 'CloudTrail.2',title: 'CloudTrail should have encryption at-rest enabled',         severity: 'MEDIUM',   count:  2 },
  ],
};

// ---- Dummy severity findings per account ----
const DUMMY_FINDINGS = {
  all: {
    CRITICAL: [
      { title: 'S3 bucket allows public read access', controlId: 'S3.8', resourceId: 'arn:aws:s3:::prod-data-exports', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'S3 bucket ACL grants public read access', controlId: 'S3.8', resourceId: 'arn:aws:s3:::analytics-raw-data', region: 'us-east-1', workflowStatus: 'NEW' },
      { title: 'Hardware MFA not enabled for root', controlId: 'IAM.6', resourceId: 'arn:aws:iam::111122223333:root', region: 'us-east-1', workflowStatus: 'NOTIFIED' },
      { title: 'Hardware MFA not enabled for root', controlId: 'IAM.6', resourceId: 'arn:aws:iam::333344445555:root', region: 'us-east-1', workflowStatus: 'NEW' },
    ],
    HIGH: [
      { title: 'Security group allows unrestricted SSH (0.0.0.0/0:22)', controlId: 'EC2.19', resourceId: 'sg-0a1b2c3d4e5f', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'Security group allows unrestricted RDP (0.0.0.0/0:3389)', controlId: 'EC2.19', resourceId: 'sg-0f1e2d3c4b5a', region: 'eu-west-1', workflowStatus: 'NOTIFIED' },
      { title: 'CloudTrail not enabled in all regions', controlId: 'CloudTrail.1', resourceId: 'arn:aws:cloudtrail:ap-south-1:222233334444:trail/default', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'Lambda function policy allows public access', controlId: 'Lambda.1', resourceId: 'arn:aws:lambda:ap-south-1:111122223333:function:data-processor', region: 'ap-south-1', workflowStatus: 'NEW' },
    ],
    MEDIUM: [
      { title: 'RDS instance not encrypted at rest', controlId: 'RDS.3', resourceId: 'arn:aws:rds:ap-south-1:111122223333:db:prod-mysql-01', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'RDS automatic minor version upgrade disabled', controlId: 'RDS.13', resourceId: 'arn:aws:rds:ap-south-1:333344445555:db:sandbox-pg-01', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'Kinesis stream not encrypted at rest', controlId: 'Kinesis.1', resourceId: 'arn:aws:kinesis:ap-south-1:222233334444:stream/events', region: 'ap-south-1', workflowStatus: 'NOTIFIED' },
    ],
    LOW: [
      { title: 'S3 bucket versioning not enabled', controlId: 'S3.14', resourceId: 'arn:aws:s3:::dev-deployment-artifacts', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'EC2 instance not managed by SSM', controlId: 'SSM.1', resourceId: 'arn:aws:ec2:ap-south-1:333344445555:instance/i-0abc123', region: 'ap-south-1', workflowStatus: 'NEW' },
    ],
  },
  '111122223333': {
    CRITICAL: [
      { title: 'S3 bucket allows public read access', controlId: 'S3.8', resourceId: 'arn:aws:s3:::prod-data-exports', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'Hardware MFA not enabled for root', controlId: 'IAM.6', resourceId: 'arn:aws:iam::111122223333:root', region: 'us-east-1', workflowStatus: 'NOTIFIED' },
    ],
    HIGH: [
      { title: 'Security group allows unrestricted SSH (0.0.0.0/0:22)', controlId: 'EC2.19', resourceId: 'sg-0a1b2c3d4e5f', region: 'ap-south-1', workflowStatus: 'NEW' },
      { title: 'Lambda function policy allows public access', controlId: 'Lambda.1', resourceId: 'arn:aws:lambda:ap-south-1:111122223333:function:data-processor', region: 'ap-south-1', workflowStatus: 'NEW' },
    ],
    MEDIUM: [
      { title: 'RDS instance not encrypted at rest', controlId: 'RDS.3', resourceId: 'arn:aws:rds:ap-south-1:111122223333:db:prod-mysql-01', region: 'ap-south-1', workflowStatus: 'NEW' },
    ],
    LOW: [
      { title: 'S3 bucket versioning not enabled', controlId: 'S3.14', resourceId: 'arn:aws:s3:::prod-config-backup', region: 'ap-south-1', workflowStatus: 'NEW' },
    ],
  },
};

// ---- Dummy Trusted Advisor data ----
const DUMMY_TA = {
  all: {
    accountId: 'all', totalError: 9, totalWarning: 14, totalOk: 112,
    lastRefresh: '2026-08-12 03:14 UTC',
    checks: [
      { id: 'ta001', name: 'Low Utilization Amazon EC2 Instances', category: 'cost_optimizing', status: 'error', resourcesSummary: { resourcesFlagged: 6 }, estimatedMonthlySavings: 412.50 },
      { id: 'ta002', name: 'Security Groups - Unrestricted Access', category: 'security', status: 'error', resourcesSummary: { resourcesFlagged: 11 }, estimatedMonthlySavings: null },
      { id: 'ta003', name: 'Amazon RDS Idle DB Instances', category: 'cost_optimizing', status: 'error', resourcesSummary: { resourcesFlagged: 3 }, estimatedMonthlySavings: 186.20 },
      { id: 'ta004', name: 'Underutilized Amazon EBS Volumes', category: 'cost_optimizing', status: 'warning', resourcesSummary: { resourcesFlagged: 8 }, estimatedMonthlySavings: 94.40 },
      { id: 'ta005', name: 'Amazon Route 53 Latency Resource Record Sets', category: 'performance', status: 'warning', resourcesSummary: { resourcesFlagged: 2 }, estimatedMonthlySavings: null },
      { id: 'ta006', name: 'Service Limits', category: 'service_limits', status: 'warning', resourcesSummary: { resourcesFlagged: 4 }, estimatedMonthlySavings: null },
      { id: 'ta007', name: 'Amazon S3 Bucket Permissions', category: 'security', status: 'error', resourcesSummary: { resourcesFlagged: 5 }, estimatedMonthlySavings: null },
      { id: 'ta008', name: 'Amazon RDS Backups', category: 'fault_tolerance', status: 'warning', resourcesSummary: { resourcesFlagged: 3 }, estimatedMonthlySavings: null },
      { id: 'ta009', name: 'MFA on Root Account', category: 'security', status: 'error', resourcesSummary: { resourcesFlagged: 2 }, estimatedMonthlySavings: null },
      { id: 'ta010', name: 'Amazon EC2 Availability Zone Balance', category: 'fault_tolerance', status: 'ok', resourcesSummary: { resourcesFlagged: 0 }, estimatedMonthlySavings: null },
    ],
  },
};

// Helper — get TA data for a given account (fall back to all-accounts summary)
function getTaData(accountId) {
  return DUMMY_TA[accountId] || { ...DUMMY_TA.all, accountId };
}

// Helper — get findings for a given account+severity
function getFindingsForSeverity(accountId, severity) {
  const pool = DUMMY_FINDINGS[accountId] || DUMMY_FINDINGS['all'];
  return (pool[severity] || []);
}

// ============================================================
// UI Components
// ============================================================

const SEVERITY_STYLES = {
  CRITICAL: { text: 'text-[#E5484D]', bg: 'bg-[#E5484D]/10', ring: 'ring-[#E5484D]/30' },
  HIGH:     { text: 'text-[#F5A623]', bg: 'bg-[#F5A623]/10', ring: 'ring-[#F5A623]/30' },
  MEDIUM:   { text: 'text-[#5B9BD5]', bg: 'bg-[#5B9BD5]/10', ring: 'ring-[#5B9BD5]/30' },
  LOW:      { text: 'text-[#8A96A3]', bg: 'bg-[#8A96A3]/10', ring: 'ring-[#8A96A3]/30' },
};

const TA_STYLES = {
  error:   { text: 'text-[#E5484D]', bg: 'bg-[#E5484D]/10', ring: 'ring-[#E5484D]/30', label: 'Action Required' },
  warning: { text: 'text-[#F5A623]', bg: 'bg-[#F5A623]/10', ring: 'ring-[#F5A623]/30', label: 'Investigate' },
  ok:      { text: 'text-[#3DD68C]', bg: 'bg-[#3DD68C]/10', ring: 'ring-[#3DD68C]/30', label: 'No Problems' },
};

function ScoreDial({ score }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? '#3DD68C' : score >= 60 ? '#F5A623' : '#E5484D';
  return (
    <div className="relative w-36 h-36 flex items-center justify-center">
      <svg width="144" height="144" viewBox="0 0 144 144" className="-rotate-90">
        <circle cx="72" cy="72" r={radius} fill="none" stroke="#1B2430" strokeWidth="10" />
        <circle cx="72" cy="72" r={radius} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 700ms ease-out' }} />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-mono text-3xl font-semibold text-[#E8EBEF] tabular-nums">{score}</span>
        <span className="text-[10px] tracking-[0.15em] text-[#8A96A3] uppercase mt-0.5">Compliant</span>
      </div>
    </div>
  );
}

function CountCard({ label, value, severity, Icon, onClick, active }) {
  const s = SEVERITY_STYLES[severity];
  return (
    <button onClick={onClick}
      className={`flex-1 min-w-[130px] text-left rounded-lg border ${active ? 'border-[#8A96A3]' : 'border-[#28323F]'} ${s.bg} px-4 py-3.5 transition-colors hover:border-[#5B6673] cursor-pointer`}>
      <div className="flex items-center justify-between mb-2">
        <span className={`text-[10px] tracking-[0.12em] uppercase font-medium ${s.text}`}>{severity}</span>
        <Icon size={14} className={s.text} strokeWidth={2} />
      </div>
      <span className="font-mono text-2xl font-semibold text-[#E8EBEF] tabular-nums">{value}</span>
      <p className="text-xs text-[#8A96A3] mt-0.5">{label}</p>
    </button>
  );
}

function TrustedAdvisorTab({ accountId }) {
  const [selectedStatus, setSelectedStatus] = useState(null);
  const summary = getTaData(accountId);
  const toggleStatus = (s) => setSelectedStatus((c) => c === s ? null : s);
  const visibleChecks = selectedStatus ? summary.checks.filter(c => c.status === selectedStatus) : summary.checks;

  return (
    <div>
      <div className="flex flex-wrap gap-3 mb-6">
        {['error', 'warning', 'ok'].map((status) => {
          const s = TA_STYLES[status];
          const countKey = status === 'error' ? 'totalError' : status === 'warning' ? 'totalWarning' : 'totalOk';
          const active = selectedStatus === status;
          return (
            <button key={status} onClick={() => toggleStatus(status)}
              className={`flex-1 min-w-[150px] text-left rounded-lg border ${active ? 'border-[#8A96A3]' : 'border-[#28323F]'} ${s.bg} px-4 py-3.5 transition-colors hover:border-[#5B6673] cursor-pointer`}>
              <span className={`text-[10px] tracking-[0.12em] uppercase font-medium ${s.text}`}>{s.label}</span>
              <div className="font-mono text-2xl font-semibold text-[#E8EBEF] tabular-nums mt-1">{summary[countKey]}</div>
              <p className="text-xs text-[#8A96A3] mt-0.5">checks</p>
            </button>
          );
        })}
      </div>
      <p className="text-[11px] text-[#5B6673] mb-3 font-mono">Last refreshed: {summary.lastRefresh}</p>
      <div className="rounded-xl border border-[#1F2933] bg-[#131B24]">
        <div className="px-5 py-4 border-b border-[#1F2933] flex items-center justify-between">
          <h2 className="text-sm font-medium">
            {selectedStatus ? `${TA_STYLES[selectedStatus].label} checks` : 'All checks'} ({visibleChecks.length})
          </h2>
          {selectedStatus && (
            <button onClick={() => setSelectedStatus(null)} className="text-[11px] text-[#5B6673] hover:text-[#E8EBEF] transition-colors">Clear filter ✕</button>
          )}
        </div>
        <div className="max-h-[480px] overflow-y-auto">
          {visibleChecks.length === 0 && <p className="px-5 py-6 text-sm text-[#5B6673]">No checks in this category.</p>}
          {visibleChecks.map((c, i) => {
            const s = TA_STYLES[c.status] || TA_STYLES.ok;
            return (
              <div key={c.id} className={`px-5 py-3 ${i !== visibleChecks.length - 1 ? 'border-b border-[#1B2430]' : ''}`}>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm text-[#C7CED6]">{c.name}</p>
                  <span className={`text-[10px] tracking-wide uppercase font-medium px-2 py-0.5 rounded ${s.bg} ${s.text} ring-1 ${s.ring} shrink-0 ml-3`}>{c.status}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-[#5B6673] font-mono">
                  <span className="capitalize">{c.category?.replace('_', ' ')}</span>
                  {c.resourcesSummary?.resourcesFlagged != null && <span>{c.resourcesSummary.resourcesFlagged} resources flagged</span>}
                  {c.estimatedMonthlySavings != null && <span>${Number(c.estimatedMonthlySavings).toFixed(2)}/mo potential savings</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// Main Dashboard
// ============================================================

export default function SecurityHubDashboard() {
  const [activeTab, setActiveTab] = useState('securityhub');
  const [accountId, setAccountId] = useState('all');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [reportFormat, setReportFormat] = useState('pdf');
  const [selectedSeverity, setSelectedSeverity] = useState(null);

  const data = DUMMY_SUMMARIES[accountId] || DUMMY_SUMMARIES['all'];
  const topControls = DUMMY_CONTROLS[accountId] || DUMMY_CONTROLS['all'];
  const severityFindings = selectedSeverity ? getFindingsForSeverity(accountId, selectedSeverity) : [];

  const accountLabel = useMemo(
    () => DUMMY_ACCOUNTS.find((a) => a.id === accountId)?.name ?? 'All Accounts',
    [accountId]
  );

  const toggleSeverity = (sev) => setSelectedSeverity((c) => c === sev ? null : sev);

  const handleDownload = () => {
    setDownloading(true);
    // POC: simulate a 1.2s "preparing" delay then show a toast instead of hitting real S3
    setTimeout(() => {
      setDownloading(false);
      alert('POC Demo — report download is disabled in this demo build.\nIn production, this generates a real presigned S3 URL.');
    }, 1200);
  };

  return (
    <div className="min-h-screen bg-[#0F1720] text-[#E8EBEF] font-sans">
      {/* POC banner */}
      <div className="bg-[#F5A623]/20 border-b border-[#F5A623]/40 px-6 py-2 flex items-center justify-center gap-2">
        <span className="text-[11px] font-mono tracking-wide text-[#F5A623] uppercase font-bold">POC Demo</span>
        <span className="text-[11px] text-[#C7CED6]">— All data is simulated. No AWS connection. For stakeholder walkthrough only.</span>
      </div>

      <div className="max-w-5xl mx-auto px-6 py-10">
        {/* Header */}
        <div className="flex items-start justify-between mb-8 pb-6 border-b border-[#1F2933]">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-[#3DD68C]" />
              <span className="text-[11px] tracking-[0.15em] uppercase text-[#8A96A3] font-mono">
                Security Hub · Compliance Report
              </span>
            </div>
            <h1 className="text-2xl font-semibold tracking-tight" style={{ fontFamily: 'Georgia, serif' }}>
              Cloud Security Posture
            </h1>
          </div>

          {/* Account selector */}
          <div className="relative">
            <button onClick={() => setDropdownOpen(!dropdownOpen)}
              className="flex items-center gap-2 rounded-md border border-[#28323F] bg-[#151D27] px-3.5 py-2 text-sm hover:border-[#3D4A5C] transition-colors">
              <span className="text-[#8A96A3] text-xs">Account:</span>
              <span className="font-medium">{accountLabel}</span>
              <ChevronDown size={14} className={`text-[#8A96A3] transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
            </button>
            {dropdownOpen && (
              <div className="absolute right-0 mt-1.5 w-64 rounded-md border border-[#28323F] bg-[#151D27] shadow-xl z-10 overflow-hidden">
                {DUMMY_ACCOUNTS.map((a) => (
                  <button key={a.id} onClick={() => { setAccountId(a.id); setDropdownOpen(false); setSelectedSeverity(null); }}
                    className={`w-full text-left px-3.5 py-2.5 text-sm hover:bg-[#1B2430] transition-colors flex items-center justify-between ${accountId === a.id ? 'bg-[#1B2430]' : ''}`}>
                    <span>{a.name}</span>
                    {a.accountId && <span className="font-mono text-[11px] text-[#5B6673]">{a.accountId}</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center gap-1 mb-6 border-b border-[#1F2933]">
          {[{ id: 'securityhub', label: 'Security Hub' }, { id: 'trustedadvisor', label: 'Trusted Advisor' }].map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${activeTab === tab.id ? 'border-[#E8EBEF] text-[#E8EBEF]' : 'border-transparent text-[#5B6673] hover:text-[#8A96A3]'}`}>
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'securityhub' && (
          <>
            {/* Score + severity cards */}
            <div className="flex flex-col md:flex-row gap-6 mb-6">
              <div className="rounded-xl border border-[#1F2933] bg-[#131B24] px-6 py-5 flex items-center gap-6">
                <ScoreDial score={data.score} />
                <div>
                  <p className="text-sm text-[#8A96A3] mb-1">Overall compliance score</p>
                  <p className="text-xs text-[#5B6673] flex items-center gap-1.5 mb-1.5">
                    <Clock size={12} /> Last scan: <span className="font-mono">{data.lastScan}</span>
                  </p>
                  <p className="text-[11px] text-[#3D4A5C] font-mono">
                    {data.passedControls} passed / {data.totalEnabledControls} enabled controls
                    {' '}<span className="text-[#5B6673]">(matches AWS Security Hub console formula)</span>
                  </p>
                </div>
              </div>
              <div className="flex-1 flex flex-wrap gap-3">
                <CountCard label="findings open" value={data.critical} severity="CRITICAL" Icon={AlertTriangle} onClick={() => toggleSeverity('CRITICAL')} active={selectedSeverity === 'CRITICAL'} />
                <CountCard label="findings open" value={data.high}     severity="HIGH"     Icon={ShieldAlert}  onClick={() => toggleSeverity('HIGH')}     active={selectedSeverity === 'HIGH'} />
                <CountCard label="findings open" value={data.medium}   severity="MEDIUM"   Icon={Activity}     onClick={() => toggleSeverity('MEDIUM')}   active={selectedSeverity === 'MEDIUM'} />
                <CountCard label="findings open" value={data.low}      severity="LOW"      Icon={ShieldCheck}  onClick={() => toggleSeverity('LOW')}      active={selectedSeverity === 'LOW'} />
              </div>
            </div>

            {/* Top failing controls */}
            <div className="rounded-xl border border-[#1F2933] bg-[#131B24] mb-6">
              <div className="px-5 py-4 border-b border-[#1F2933] flex items-center justify-between">
                <h2 className="text-sm font-medium">Top failing controls</h2>
                <span className="text-[11px] text-[#5B6673] font-mono">{accountLabel}</span>
              </div>
              <div>
                {topControls.length === 0 && <p className="px-5 py-6 text-sm text-[#5B6673]">No control data for this account yet.</p>}
                {topControls.map((c, i) => {
                  const s = SEVERITY_STYLES[c.severity] || SEVERITY_STYLES.LOW;
                  return (
                    <div key={c.id} className={`flex items-center gap-4 px-5 py-3.5 ${i !== topControls.length - 1 ? 'border-b border-[#1B2430]' : ''}`}>
                      <span className="font-mono text-xs text-[#5B6673] w-16 shrink-0">{c.id}</span>
                      <span className="text-sm text-[#C7CED6] flex-1">{c.title}</span>
                      <span className={`text-[10px] tracking-wide uppercase font-medium px-2 py-0.5 rounded ${s.bg} ${s.text} ring-1 ${s.ring} shrink-0`}>{c.severity}</span>
                      <span className="font-mono text-sm text-[#E8EBEF] w-8 text-right shrink-0">{c.count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Severity drill-down panel */}
            {selectedSeverity && (
              <div className="rounded-xl border border-[#1F2933] bg-[#131B24] mb-6">
                <div className="px-5 py-4 border-b border-[#1F2933] flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] tracking-wide uppercase font-medium px-2 py-0.5 rounded ${SEVERITY_STYLES[selectedSeverity].bg} ${SEVERITY_STYLES[selectedSeverity].text} ring-1 ${SEVERITY_STYLES[selectedSeverity].ring}`}>
                      {selectedSeverity}
                    </span>
                    <h2 className="text-sm font-medium">{severityFindings.length} finding{severityFindings.length !== 1 ? 's' : ''}</h2>
                  </div>
                  <button onClick={() => setSelectedSeverity(null)} className="text-[11px] text-[#5B6673] hover:text-[#E8EBEF] transition-colors">Close ✕</button>
                </div>
                <div className="max-h-[420px] overflow-y-auto">
                  {severityFindings.length === 0 && <p className="px-5 py-6 text-sm text-[#5B6673]">No {selectedSeverity.toLowerCase()} findings for this account.</p>}
                  {severityFindings.map((f, i) => (
                    <div key={`${f.controlId}-${i}`} className={`px-5 py-3 ${i !== severityFindings.length - 1 ? 'border-b border-[#1B2430]' : ''}`}>
                      <p className="text-sm text-[#C7CED6] mb-1">{f.title}</p>
                      <div className="flex items-center gap-3 text-[11px] text-[#5B6673] font-mono">
                        <span>{f.controlId}</span>
                        <span className="truncate max-w-[320px]">{f.resourceId}</span>
                        {f.region && <span>{f.region}</span>}
                        <span>{f.workflowStatus}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Download */}
            <div className="flex items-center justify-between rounded-xl border border-[#1F2933] bg-[#131B24] px-5 py-4">
              <div>
                <p className="text-sm font-medium mb-2">Full compliance report</p>
                <div className="flex items-center gap-4">
                  <label className="flex items-center gap-1.5 text-xs text-[#C7CED6] cursor-pointer">
                    <input type="radio" name="reportFormat" value="pdf" checked={reportFormat === 'pdf'} onChange={() => setReportFormat('pdf')} className="accent-[#E8EBEF]" />
                    PDF
                  </label>
                  <label className="flex items-center gap-1.5 text-xs text-[#C7CED6] cursor-pointer">
                    <input type="radio" name="reportFormat" value="csv" checked={reportFormat === 'csv'} onChange={() => setReportFormat('csv')} className="accent-[#E8EBEF]" />
                    CSV
                  </label>
                  <span className="text-[11px] text-[#5B6673]">
                    {reportFormat === 'csv' ? 'One row per finding · sortable by severity in Excel' : 'Formatted report · grouped by severity'}
                  </span>
                </div>
              </div>
              <button onClick={handleDownload} disabled={downloading}
                className="flex items-center gap-2 rounded-md bg-[#E8EBEF] text-[#0F1720] px-4 py-2 text-sm font-medium hover:bg-white transition-colors disabled:opacity-60">
                <Download size={15} strokeWidth={2.2} />
                {downloading ? 'Preparing…' : 'Download report'}
              </button>
            </div>
          </>
        )}

        {activeTab === 'trustedadvisor' && <TrustedAdvisorTab accountId={accountId} />}

        <p className="text-center text-[11px] text-[#3D4A5C] mt-8 font-mono">
          POC Demo · Data refreshed daily via AWS Security Hub &amp; Trusted Advisor APIs · ap-south-1
        </p>
        <p className="text-center text-[10px] text-[#2A323C] mt-1.5 font-mono">
          dashboard v{DASHBOARD_VERSION} · demo build — no live API connection
        </p>
      </div>
    </div>
  );
}
