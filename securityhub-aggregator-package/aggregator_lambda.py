"""
Runs on a schedule (EventBridge, e.g. daily 03:00 IST) in the Security Hub
DELEGATED ADMINISTRATOR account.

VERSION: 1.4.0   (bump this + add a CHANGELOG line every time you redeploy)

CHANGELOG
  1.4.0 - PDF now opens with an executive summary page (score, severity bar
          chart, new-vs-existing trend, top 3 controls) before the detail
          tables. Findings tagged NEW if first observed in the last ~26h
          (no extra state storage — uses AWS's own FirstObservedAt). New
          "Findings by Resource Type" summary table. CSV gained IsNew and
          ResourceType columns.
  1.3.0 - Real AWS-formula compliance score (passed/enabled controls,
          matches Security Hub console exactly). Fixed-height PDF table
          rows (no more multi_cell misalignment on long titles). CSV
          columns reordered with Severity first. Clean-account fix so
          100%-passing accounts still appear in the dashboard.
  1.2.0 - Added Trusted Advisor integration (cross-account role read +
          Organizational-style aggregation), CSV export, findings.json
          per-account output for click-to-drill-down severity cards.
  1.1.0 - Added PDF report generation (fpdf2), severity-grouped findings.
  1.0.0 - Initial: Security Hub findings aggregation, per-account JSON
          summaries, account index for dashboard dropdown.

Security Hub:
  Because this account is delegated admin, GetFindings already returns findings
  from all 70+ member accounts — no cross-account role needed. Each finding
  carries AwsAccountId telling you which account it belongs to.

Trusted Advisor:
  The AWS Support API is a GLOBAL service (us-east-1 only) and requires
  Business+/Enterprise support plan. TA data is per-account, so we assume
  a lightweight cross-account role (TA_READER_ROLE_NAME) in each member
  account to call DescribeTrustedAdvisorChecks / DescribeTrustedAdvisorCheckResult.
  The delegated-admin account itself is queried using its own credentials.

  Required IAM permissions on the Lambda execution role:
    - sts:AssumeRole  (to assume TA_READER_ROLE_NAME in member accounts)
    - support:DescribeTrustedAdvisorChecks
    - support:DescribeTrustedAdvisorCheckResult

  Required IAM permissions on TA_READER_ROLE_NAME in EVERY member account:
    - support:DescribeTrustedAdvisorChecks
    - support:DescribeTrustedAdvisorCheckResult
    Trust policy must allow the Lambda execution role ARN to assume it.

Writes to S3:
  summaries/accounts.json                    <- account list (dropdown)
  summaries/{account_id}/latest.json         <- per-account Security Hub summary
  summaries/{account_id}/findings.json       <- condensed findings (click-to-drill-down)
  summaries/all/latest.json                  <- all-accounts Security Hub summary
  summaries/all/findings.json                <- all-accounts condensed findings
  trusted-advisor/{account_id}/latest.json   <- per-account TA summary
  trusted-advisor/all/latest.json            <- all-accounts TA summary
  reports/{account_id}/latest.pdf            <- per-account PDF (Security Hub)
  reports/{account_id}/latest.csv            <- per-account CSV (Security Hub)
  reports/all/latest.pdf                     <- combined PDF
  reports/all/latest.csv                     <- combined CSV
"""

AGGREGATOR_VERSION = '1.4.0'



import boto3
import json
import csv
import io
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from fpdf import FPDF, XPos, YPos

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

securityhub = boto3.client('securityhub')
s3 = boto3.client('s3')
sts = boto3.client('sts')

BUCKET = 'securityhub-dashboard-data'

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

# A finding counts as "new since last scan" if AWS's own FirstObservedAt
# timestamp falls within this window. 26h (not 24h) gives a buffer for
# schedule drift/Lambda start delay on a daily run — adjust if you change
# the EventBridge schedule frequency.
NEW_FINDING_WINDOW_HOURS = 26


def is_new_finding(f, now):
    """True if this finding's FirstObservedAt is within the new-finding
    window. Uses AWS's own timestamp — no extra state/snapshot storage
    needed to detect what's new since the last run."""
    observed = f.get('FirstObservedAt')
    if not observed:
        return False
    try:
        observed_dt = datetime.strptime(observed, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            observed_dt = datetime.strptime(observed, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        except ValueError:
            return False
    return (now - observed_dt) <= timedelta(hours=NEW_FINDING_WINDOW_HOURS)


def get_resource_type(f):
    """Extract the AWS resource type (e.g. 'AwsS3Bucket', 'AwsEc2SecurityGroup')
    from a finding, falling back to 'Unknown' if not present."""
    resources = f.get('Resources', [{}])
    return (resources[0].get('Type') if resources else None) or 'Unknown'

# ---------------------------------------------------------------------------
# Cross-account role assumed in every member account to read Trusted Advisor.
# Create this role in each member account and trust the Lambda execution role.
# ---------------------------------------------------------------------------
TA_READER_ROLE_NAME = 'TrustedAdvisorReadOnlyRole'

# Optional: map account IDs to friendly names (pulled from Organizations by
# default — see get_account_names() below)
ACCOUNT_NAME_OVERRIDES = {
    '143301474150': 'audit',
    '824623333855': 'AmazonAWS',
}


def get_account_names():
    """Pull friendly names directly from AWS Organizations."""
    org = boto3.client('organizations')
    names = {}
    paginator = org.get_paginator('list_accounts')
    for page in paginator.paginate():
        for acct in page['Accounts']:
            names[acct['Id']] = acct['Name']
    names.update(ACCOUNT_NAME_OVERRIDES)
    return names


# ---------------------------------------------------------------------------
# Security Hub
# ---------------------------------------------------------------------------

def fetch_all_findings():
    """Paginate through GetFindings for ACTIVE, non-suppressed OPEN findings only.
    This is used for severity counts / top controls / PDF-CSV report content —
    i.e. 'what still needs attention'. It intentionally excludes PASSED findings."""
    findings = []
    paginator = securityhub.get_paginator('get_findings')
    page_iterator = paginator.paginate(
        Filters={
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
            'WorkflowStatus': [
                {'Value': 'NEW', 'Comparison': 'EQUALS'},
                {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'},
            ],
        },
        PaginationConfig={'PageSize': 100},
    )
    for page in page_iterator:
        findings.extend(page['Findings'])
    return findings


def fetch_all_compliance_findings():
    """Paginate through GetFindings for ALL ACTIVE findings regardless of
    workflow status — this includes PASSED findings, which fetch_all_findings()
    deliberately excludes. Needed to replicate AWS's own security score formula,
    which is based on per-control Pass/Fail/Warning status, not just open findings."""
    findings = []
    paginator = securityhub.get_paginator('get_findings')
    page_iterator = paginator.paginate(
        Filters={
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        },
        PaginationConfig={'PageSize': 100},
    )
    for page in page_iterator:
        findings.extend(page['Findings'])
    return findings


def compute_control_scores(compliance_findings):
    """Replicates AWS Security Hub's official security score formula:

        score = (passed controls / enabled controls) * 100

    where 'enabled controls' = controls with a Compliance.Status of
    PASSED, FAILED, or WARNING. Controls with NOT_AVAILABLE ('No data')
    are excluded from both numerator and denominator, matching AWS's
    documented behaviour exactly.

    A control's overall status per account is the worst status seen among
    its findings: FAILED > WARNING > PASSED > NOT_AVAILABLE. This mirrors
    how Security Hub itself rolls up multiple findings under one control.

    Returns (per_account_scores, all_accounts_score) where each is:
        {'passedControls': int, 'failedControls': int, 'warningControls': int,
         'totalEnabledControls': int, 'score': int}
    """
    STATUS_RANK = {'FAILED': 3, 'WARNING': 2, 'PASSED': 1, 'NOT_AVAILABLE': 0}

    # (account_id, control_id) -> worst status seen
    control_status = {}

    for f in compliance_findings:
        acct = f.get('AwsAccountId', 'UNKNOWN')
        control_id = f.get('ProductFields', {}).get('ControlId') or f.get('GeneratorId', 'UNKNOWN')
        status = f.get('Compliance', {}).get('Status', 'NOT_AVAILABLE')
        key = (acct, control_id)

        if key not in control_status or STATUS_RANK.get(status, 0) > STATUS_RANK.get(control_status[key], 0):
            control_status[key] = status

    def _score_from_counts(passed, failed, warning):
        enabled = passed + failed + warning
        if enabled == 0:
            return 0
        return round((passed / enabled) * 100)

    per_account = defaultdict(lambda: {'passedControls': 0, 'failedControls': 0, 'warningControls': 0})
    for (acct, _control_id), status in control_status.items():
        if status == 'PASSED':
            per_account[acct]['passedControls'] += 1
        elif status == 'FAILED':
            per_account[acct]['failedControls'] += 1
        elif status == 'WARNING':
            per_account[acct]['warningControls'] += 1
        # NOT_AVAILABLE is intentionally not counted at all

    per_account_scores = {}
    total_passed = total_failed = total_warning = 0
    for acct, counts in per_account.items():
        enabled = counts['passedControls'] + counts['failedControls'] + counts['warningControls']
        per_account_scores[acct] = {
            **counts,
            'totalEnabledControls': enabled,
            'score': _score_from_counts(counts['passedControls'], counts['failedControls'], counts['warningControls']),
        }
        total_passed += counts['passedControls']
        total_failed += counts['failedControls']
        total_warning += counts['warningControls']

    all_accounts_score = {
        'passedControls': total_passed,
        'failedControls': total_failed,
        'warningControls': total_warning,
        'totalEnabledControls': total_passed + total_failed + total_warning,
        'score': _score_from_counts(total_passed, total_failed, total_warning),
    }

    return per_account_scores, all_accounts_score


def summarize_by_account(findings):
    """Group OPEN findings by AwsAccountId and compute per-account severity
    counts / top controls. The 'score' field here is a placeholder overwritten
    later with the real AWS-formula score from compute_control_scores() —
    kept here only so the dict shape is consistent if that step is skipped.
    Returns (summaries, by_account)."""
    by_account = defaultdict(list)
    for f in findings:
        acct = f.get('AwsAccountId', 'UNKNOWN')
        by_account[acct].append(f)

    summaries = {}
    for account_id, acct_findings in by_account.items():
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        control_counts = {}

        for f in acct_findings:
            sev = f.get('Severity', {}).get('Label', 'LOW')
            if sev in severity_counts:
                severity_counts[sev] += 1

            control_id = f.get('ProductFields', {}).get('ControlId') or f.get('GeneratorId', 'UNKNOWN')
            title = f.get('Title', 'Unknown control')
            if control_id not in control_counts:
                control_counts[control_id] = {'id': control_id, 'title': title, 'severity': sev, 'count': 0}
            control_counts[control_id]['count'] += 1

        top_controls = sorted(control_counts.values(), key=lambda x: -x['count'])[:5]

        summaries[account_id] = {
            'accountId': account_id,
            'critical': severity_counts['CRITICAL'],
            'high': severity_counts['HIGH'],
            'medium': severity_counts['MEDIUM'],
            'low': severity_counts['LOW'],
            'score': 0,  # overwritten in lambda_handler with the real AWS-formula score
            'lastScan': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            'topControls': top_controls,
        }
    return summaries, by_account


def condense_finding(f):
    """Small, frontend-friendly shape for a single Security Hub finding."""
    resources = f.get('Resources', [{}])
    return {
        'severity': f.get('Severity', {}).get('Label', 'LOW'),
        'title': f.get('Title', 'Unknown finding'),
        'resourceId': resources[0].get('Id', 'unknown') if resources else 'unknown',
        'controlId': f.get('ProductFields', {}).get('ControlId') or f.get('GeneratorId', 'UNKNOWN'),
        'workflowStatus': f.get('Workflow', {}).get('Status', 'UNKNOWN'),
        'region': f.get('Region', ''),
        'firstObservedAt': f.get('FirstObservedAt', ''),
    }


def build_pdf_report(account_id, account_name, summary, findings):
    """Builds a report with three parts, in order:
      1. Executive summary page — score, severity bar chart, new-vs-existing
         delta, top 3 failing controls. Meant to be readable standalone.
      2. Full findings detail, grouped Critical -> High -> Medium -> Low,
         with a NEW badge on findings first observed since the last run.
      3. Findings-by-resource-type summary table — which AWS services are
         contributing the most findings, at a glance.
    Returns raw bytes.

    Uses fixed-height table rows (no multi_cell) so wrapping long titles can
    never desync a row's cell borders — every row stays on one baseline,
    with text truncated to fit instead of wrapping.
    """
    now = datetime.now(timezone.utc)
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.set_margins(10, 10, 10)
    pdf.set_auto_page_break(auto=True, margin=12)

    def row(*cells_and_widths, h=6, fill=False):
        """Write one fixed-height table row. Args alternate (text, width)."""
        pairs = list(zip(cells_and_widths[::2], cells_and_widths[1::2]))
        for i, (text, w) in enumerate(pairs):
            is_last = (i == len(pairs) - 1)
            pdf.cell(
                w, h, str(text), border=1, fill=fill,
                new_x=XPos.RIGHT if not is_last else XPos.LMARGIN,
                new_y=YPos.TOP if not is_last else YPos.NEXT,
            )

    fill_by_severity = {
        'CRITICAL': (245, 220, 220),
        'HIGH': (250, 235, 215),
        'MEDIUM': (255, 250, 210),
        'LOW': (235, 235, 235),
    }
    bar_color_by_severity = {
        'CRITICAL': (229, 72, 77),
        'HIGH': (245, 166, 35),
        'MEDIUM': (91, 155, 213),
        'LOW': (138, 150, 163),
    }

    # Precompute which findings are new, and group by severity / resource type
    new_findings = [f for f in findings if is_new_finding(f, now)]
    existing_findings = [f for f in findings if f not in new_findings]

    by_severity = defaultdict(list)
    for f in findings:
        sev = f.get('Severity', {}).get('Label', 'LOW')
        by_severity[sev].append(f)
    ordered_severities = SEVERITY_ORDER + [s for s in by_severity if s not in SEVERITY_ORDER]

    by_resource_type = defaultdict(list)
    for f in findings:
        by_resource_type[get_resource_type(f)].append(f)

    # =====================================================================
    # PAGE 1 — EXECUTIVE SUMMARY
    # =====================================================================
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 9, 'AWS Security Hub Compliance Report', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, f'Account: {account_name}  ({account_id})', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f'Generated: {summary["lastScan"]}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # ── Compliance score ───────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 8, f'Compliance Score: {summary["score"]} / 100', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(90, 90, 90)
    passed = summary.get('passedControls', 0)
    total_enabled = summary.get('totalEnabledControls', 0)
    pdf.cell(0, 5, f'{passed} passed / {total_enabled} enabled controls (matches AWS Security Hub console formula)',
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # ── Severity distribution bar chart ───────────────────────────────
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 7, 'Severity Distribution', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    sev_counts = {
        'CRITICAL': summary['critical'], 'HIGH': summary['high'],
        'MEDIUM': summary['medium'], 'LOW': summary['low'],
    }
    max_count = max(sev_counts.values()) or 1
    max_bar_w = 140
    label_w = 22
    for sev in SEVERITY_ORDER:
        count = sev_counts[sev]
        bar_w = (count / max_count) * max_bar_w
        y_start = pdf.get_y()
        pdf.set_font('Helvetica', 'B', 8)
        pdf.cell(label_w, 6, sev, new_x=XPos.RIGHT, new_y=YPos.TOP)
        if bar_w > 0:
            pdf.set_fill_color(*bar_color_by_severity[sev])
            pdf.cell(bar_w, 6, '', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_xy(10 + label_w + bar_w + 2, y_start)
        pdf.cell(15, 6, str(count), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── New vs. existing (trend/delta) ────────────────────────────────
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 7, 'Since Last Scan', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 9)
    new_crit_high = sum(1 for f in new_findings if f.get('Severity', {}).get('Label') in ('CRITICAL', 'HIGH'))
    pdf.set_text_color(190, 40, 40) if new_findings else pdf.set_text_color(60, 140, 80)
    pdf.cell(0, 6,
             f'{len(new_findings)} new finding{"s" if len(new_findings) != 1 else ""} '
             f'(first observed in the last ~{NEW_FINDING_WINDOW_HOURS}h)'
             + (f'  \u2014  {new_crit_high} of them Critical/High' if new_crit_high else ''),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(110, 110, 110)
    pdf.cell(0, 5, f'{len(existing_findings)} ongoing finding{"s" if len(existing_findings) != 1 else ""} (open before this window)',
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # ── Top 3 failing controls ─────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 7, 'Top Failing Controls', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(210, 210, 210)
    row('Control ID', 30, 'Title', 100, 'Severity', 30, 'Count', 30, h=7, fill=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_fill_color(255, 255, 255)
    for c in summary.get('topControls', [])[:3]:
        row(str(c['id'])[:18], 30, str(c['title'])[:60], 100, str(c['severity']), 30, str(c['count']), 30, h=6)

    # =====================================================================
    # PAGE 2+ — FULL FINDINGS DETAIL, GROUPED BY SEVERITY, NEW BADGE
    # =====================================================================
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, f'All Findings ({len(findings)} total)', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    for sev in ordered_severities:
        sev_findings = by_severity.get(sev, [])
        if not sev_findings:
            continue

        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 8, f'{sev} ({len(sev_findings)})', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(210, 210, 210)
        row('New?', 12, 'Control ID', 28, 'Finding Title', 82, 'Resource', 48, 'Region', 20, h=7, fill=True)

        pdf.set_font('Helvetica', '', 7)
        pdf.set_fill_color(*fill_by_severity.get(sev, (255, 255, 255)))
        # Sorted so NEW findings surface first, then by control id
        sorted_findings = sorted(
            sev_findings,
            key=lambda f: (not is_new_finding(f, now), f.get('ProductFields', {}).get('ControlId') or '')
        )
        for f in sorted_findings:
            badge = 'NEW' if is_new_finding(f, now) else ''
            control_id = (f.get('ProductFields', {}).get('ControlId') or f.get('GeneratorId', ''))[:15]
            title = f.get('Title', 'Unknown finding')[:50]
            resources = f.get('Resources', [{}])
            resource_id = resources[0].get('Id', 'unknown') if resources else 'unknown'
            resource_short = resource_id[-30:] if len(resource_id) > 30 else resource_id
            region = f.get('Region', '')[:10]
            row(badge, 12, control_id, 28, title, 82, resource_short, 48, region, 20, h=6, fill=True)
        pdf.ln(4)

    # =====================================================================
    # PAGE N — FINDINGS BY RESOURCE TYPE
    # =====================================================================
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, 'Findings by Resource Type', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(110, 110, 110)
    pdf.cell(0, 5, 'Which AWS services are contributing the most findings, across all severities.',
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(210, 210, 210)
    row('Resource Type', 66, 'Critical', 26, 'High', 26, 'Medium', 26, 'Low', 26, 'Total', 20, h=7, fill=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_fill_color(255, 255, 255)

    type_rows = []
    for rtype, flist in by_resource_type.items():
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in flist:
            sev = f.get('Severity', {}).get('Label', 'LOW')
            if sev in counts:
                counts[sev] += 1
        type_rows.append((rtype, counts, len(flist)))
    type_rows.sort(key=lambda t: -t[2])

    for rtype, counts, total in type_rows:
        row(rtype[:38], 66, str(counts['CRITICAL']), 26, str(counts['HIGH']), 26,
            str(counts['MEDIUM']), 26, str(counts['LOW']), 26, str(total), 20, h=6)

    return bytes(pdf.output())


def build_csv_report(account_id, account_name, findings):
    """CSV with one row per finding, sorted Critical -> High -> Medium -> Low,
    new findings first within each severity, then by Control ID (matches
    the PDF's ordering). Severity is the first column since that's the
    most common filter/sort users apply in Excel."""
    now = datetime.now(timezone.utc)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Severity', 'IsNew', 'ControlId', 'Title', 'ResourceType', 'ResourceId', 'Region',
        'WorkflowStatus', 'RecordState', 'FirstObservedAt', 'AccountId', 'AccountName',
    ])

    severity_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            severity_rank.get(f.get('Severity', {}).get('Label', 'LOW'), 99),
            not is_new_finding(f, now),
            f.get('ProductFields', {}).get('ControlId') or f.get('GeneratorId', ''),
        )
    )

    for f in sorted_findings:
        sev = f.get('Severity', {}).get('Label', 'LOW')
        title = f.get('Title', 'Unknown finding')
        resources = f.get('Resources', [{}])
        resource_id = resources[0].get('Id', 'unknown') if resources else 'unknown'
        resource_type = get_resource_type(f)
        control_id = f.get('ProductFields', {}).get('ControlId') or f.get('GeneratorId', 'UNKNOWN')
        workflow_status = f.get('Workflow', {}).get('Status', 'UNKNOWN')
        record_state = f.get('RecordState', 'UNKNOWN')
        first_observed = f.get('FirstObservedAt', '')
        region = f.get('Region', '')
        is_new = 'YES' if is_new_finding(f, now) else ''

        writer.writerow([
            sev, is_new, control_id, title, resource_type, resource_id, region,
            workflow_status, record_state, first_observed, account_id, account_name,
        ])

    return output.getvalue().encode('utf-8')


def generate_and_upload_reports(summaries, by_account, account_names, all_control_score):
    for account_id, summary in summaries.items():
        name = account_names.get(account_id, account_id)
        findings = by_account[account_id]

        pdf_bytes = build_pdf_report(account_id, name, summary, findings)
        s3.put_object(Bucket=BUCKET, Key=f'reports/{account_id}/latest.pdf',
                       Body=pdf_bytes, ContentType='application/pdf')

        csv_bytes = build_csv_report(account_id, name, findings)
        s3.put_object(Bucket=BUCKET, Key=f'reports/{account_id}/latest.csv',
                       Body=csv_bytes, ContentType='text/csv')

    all_findings = [f for flist in by_account.values() for f in flist]
    all_summary = {
        'critical': sum(s['critical'] for s in summaries.values()),
        'high': sum(s['high'] for s in summaries.values()),
        'medium': sum(s['medium'] for s in summaries.values()),
        'low': sum(s['low'] for s in summaries.values()),
        'score': all_control_score['score'],
        'passedControls': all_control_score['passedControls'],
        'failedControls': all_control_score['failedControls'],
        'warningControls': all_control_score['warningControls'],
        'totalEnabledControls': all_control_score['totalEnabledControls'],
        'lastScan': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'topControls': [],
    }
    pdf_bytes = build_pdf_report('ALL', 'All Accounts', all_summary, all_findings)
    s3.put_object(Bucket=BUCKET, Key='reports/all/latest.pdf',
                   Body=pdf_bytes, ContentType='application/pdf')

    csv_bytes = build_csv_report('ALL', 'All Accounts', all_findings)
    s3.put_object(Bucket=BUCKET, Key='reports/all/latest.csv',
                   Body=csv_bytes, ContentType='text/csv')


def write_to_s3(summaries, by_account, account_names, all_control_score):
    for account_id, summary in summaries.items():
        s3.put_object(Bucket=BUCKET, Key=f'summaries/{account_id}/latest.json',
                       Body=json.dumps(summary), ContentType='application/json')

        severity_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
        condensed = sorted(
            (condense_finding(f) for f in by_account[account_id]),
            key=lambda x: severity_rank.get(x['severity'], 99)
        )
        s3.put_object(Bucket=BUCKET, Key=f'summaries/{account_id}/findings.json',
                       Body=json.dumps(condensed), ContentType='application/json')

    index = [{'id': 'all', 'name': 'All Accounts', 'accountId': ''}]
    for account_id in sorted(summaries.keys()):
        index.append({
            'id': account_id,
            'name': account_names.get(account_id, account_id),
            'accountId': account_id,
        })
    s3.put_object(Bucket=BUCKET, Key='summaries/accounts.json',
                   Body=json.dumps(index), ContentType='application/json')

    all_summary = {
        'critical': sum(s['critical'] for s in summaries.values()),
        'high': sum(s['high'] for s in summaries.values()),
        'medium': sum(s['medium'] for s in summaries.values()),
        'low': sum(s['low'] for s in summaries.values()),
        'score': all_control_score['score'],
        'passedControls': all_control_score['passedControls'],
        'failedControls': all_control_score['failedControls'],
        'warningControls': all_control_score['warningControls'],
        'totalEnabledControls': all_control_score['totalEnabledControls'],
        'lastScan': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'topControls': [],
    }
    s3.put_object(Bucket=BUCKET, Key='summaries/all/latest.json',
                   Body=json.dumps(all_summary), ContentType='application/json')

    # Version metadata — lets the API/dashboard (and you, debugging later)
    # confirm which aggregator version actually produced this data, and when.
    s3.put_object(
        Bucket=BUCKET, Key='summaries/version.json',
        Body=json.dumps({
            'aggregatorVersion': AGGREGATOR_VERSION,
            'lastRun': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        }),
        ContentType='application/json',
    )

    severity_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    all_condensed = sorted(
        (condense_finding(f) for flist in by_account.values() for f in flist),
        key=lambda x: severity_rank.get(x['severity'], 99)
    )
    s3.put_object(Bucket=BUCKET, Key='summaries/all/findings.json',
                   Body=json.dumps(all_condensed), ContentType='application/json')


# ---------------------------------------------------------------------------
# Trusted Advisor
# ---------------------------------------------------------------------------

def _support_client_for_account(account_id, own_account_id):
    """Return a Support client scoped to *account_id*.
    The Support API is global (us-east-1 only). If account_id is the current
    (admin) account we use default credentials; otherwise we assume
    TA_READER_ROLE_NAME in the target account."""
    if account_id == own_account_id:
        return boto3.client('support', region_name='us-east-1')

    role_arn = f'arn:aws:iam::{account_id}:role/{TA_READER_ROLE_NAME}'
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='TrustedAdvisorAggregator',
            DurationSeconds=900,
        )['Credentials']
    except Exception as exc:
        logger.warning('Could not assume role in %s: %s', account_id, exc)
        return None

    return boto3.client(
        'support',
        region_name='us-east-1',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )


def fetch_trusted_advisor_checks(account_id, own_account_id):
    """Return a list of TA check result dicts for *account_id*.
    Returns an empty list if the Support API is unavailable so the rest of
    the aggregation is unaffected."""
    client = _support_client_for_account(account_id, own_account_id)
    if client is None:
        return []

    try:
        checks_resp = client.describe_trusted_advisor_checks(language='en')
    except Exception as exc:
        logger.warning('DescribeTrustedAdvisorChecks failed for %s: %s', account_id, exc)
        return []

    check_ids = [c['id'] for c in checks_resp.get('checks', [])]
    checks_meta = {c['id']: c for c in checks_resp.get('checks', [])}
    if not check_ids:
        return []

    results = []
    for check_id in check_ids:
        try:
            res = client.describe_trusted_advisor_check_result(
                checkId=check_id, language='en',
            ).get('result', {})
        except Exception as exc:
            logger.debug('TA result fetch failed for check %s in %s: %s', check_id, account_id, exc)
            continue

        meta = checks_meta.get(check_id, {})
        status = res.get('status', 'not_available')

        flagged = []
        for r in res.get('flaggedResources', [])[:100]:
            flagged.append({
                'status': r.get('status', 'unknown'),
                'region': r.get('region', ''),
                'metadata': r.get('metadata', []),
            })

        check_entry = {
            'id': check_id,
            'name': meta.get('name', check_id),
            'category': meta.get('category', 'unknown'),
            'description': meta.get('description', ''),
            'status': status,
            'resourcesSummary': res.get('resourcesSummary', {}),
            'flaggedResources': flagged,
        }

        cost_summary = res.get('categorySpecificSummary', {}).get('costOptimizing', {})
        if 'estimatedMonthlySavings' in cost_summary:
            check_entry['estimatedMonthlySavings'] = cost_summary['estimatedMonthlySavings']

        results.append(check_entry)

    return results


def summarize_ta_by_account(ta_by_account):
    """Convert raw per-account TA check lists into dashboard-ready summaries."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    per_account = {}

    for account_id, checks in ta_by_account.items():
        per_account[account_id] = {
            'accountId': account_id,
            'totalError': sum(1 for c in checks if c['status'] == 'error'),
            'totalWarning': sum(1 for c in checks if c['status'] == 'warning'),
            'totalOk': sum(1 for c in checks if c['status'] == 'ok'),
            'lastRefresh': now,
            'checks': checks,
        }

    STATUS_RANK = {'error': 3, 'warning': 2, 'ok': 1, 'not_available': 0}
    merged_checks = {}

    for account_id, checks in ta_by_account.items():
        for c in checks:
            cid = c['id']
            if cid not in merged_checks:
                merged_checks[cid] = {
                    'id': c['id'],
                    'name': c['name'],
                    'category': c['category'],
                    'description': c['description'],
                    'status': c['status'],
                    'resourcesSummary': dict(c.get('resourcesSummary') or {}),
                    'flaggedResources': list(c.get('flaggedResources') or []),
                    'estimatedMonthlySavings': c.get('estimatedMonthlySavings'),
                }
            else:
                existing = merged_checks[cid]
                if STATUS_RANK.get(c['status'], 0) > STATUS_RANK.get(existing['status'], 0):
                    existing['status'] = c['status']
                for key in ('resourcesProcessed', 'resourcesFlagged', 'resourcesSuppressed'):
                    existing['resourcesSummary'][key] = (
                        existing['resourcesSummary'].get(key, 0) +
                        (c.get('resourcesSummary') or {}).get(key, 0)
                    )
                if c.get('estimatedMonthlySavings') is not None:
                    existing['estimatedMonthlySavings'] = (
                        (existing.get('estimatedMonthlySavings') or 0) + c['estimatedMonthlySavings']
                    )
                remaining = 200 - len(existing['flaggedResources'])
                if remaining > 0:
                    existing['flaggedResources'].extend((c.get('flaggedResources') or [])[:remaining])

    all_checks = sorted(merged_checks.values(), key=lambda c: (-STATUS_RANK.get(c['status'], 0), c['name']))

    all_summary = {
        'accountId': 'all',
        'totalError': sum(c['status'] == 'error' for c in all_checks),
        'totalWarning': sum(c['status'] == 'warning' for c in all_checks),
        'totalOk': sum(c['status'] == 'ok' for c in all_checks),
        'lastRefresh': now,
        'checks': all_checks,
    }

    return per_account, all_summary


def write_ta_to_s3(ta_summaries_by_account, ta_all_summary):
    for account_id, summary in ta_summaries_by_account.items():
        s3.put_object(
            Bucket=BUCKET, Key=f'trusted-advisor/{account_id}/latest.json',
            Body=json.dumps(summary, default=str), ContentType='application/json',
        )
    s3.put_object(
        Bucket=BUCKET, Key='trusted-advisor/all/latest.json',
        Body=json.dumps(ta_all_summary, default=str), ContentType='application/json',
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    account_names = get_account_names()
    own_account_id = sts.get_caller_identity()['Account']
    logger.info('Running as account %s, processing %d known accounts', own_account_id, len(account_names))
    logger.info('Aggregator version: %s', AGGREGATOR_VERSION)

    # --- Security Hub: open findings (drives severity counts / top controls / reports) ---
    findings = fetch_all_findings()
    summaries, by_account = summarize_by_account(findings)

    # --- Security Hub: real AWS-formula score (passed / (passed+failed+warning) controls) ---
    compliance_findings = fetch_all_compliance_findings()
    per_account_scores, all_accounts_score = compute_control_scores(compliance_findings)

    for account_id, summary in summaries.items():
        control_score = per_account_scores.get(account_id, {
            'passedControls': 0, 'failedControls': 0, 'warningControls': 0,
            'totalEnabledControls': 0, 'score': 0,
        })
        summary.update(control_score)  # overwrites 'score' + adds passed/failed/warning/total fields

    # Accounts with a clean record (all controls passed) have zero OPEN findings
    # and would otherwise be missing from `summaries` entirely — add them back in
    # with zeroed severity counts so they still show up in the dashboard.
    for account_id, control_score in per_account_scores.items():
        if account_id in summaries or not account_id:
            continue
        summaries[account_id] = {
            'accountId': account_id,
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'lastScan': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            'topControls': [],
            **control_score,
        }
        by_account[account_id] = []  # no open findings to include in its PDF/CSV

    write_to_s3(summaries, by_account, account_names, all_accounts_score)
    generate_and_upload_reports(summaries, by_account, account_names, all_accounts_score)
    logger.info('Security Hub: wrote summaries/reports for %d accounts (score formula matches AWS console)', len(summaries))

    # --- Trusted Advisor ---
    all_account_ids = set(summaries.keys()) | set(account_names.keys())
    all_account_ids.discard('')

    ta_by_account = {}
    ta_errors = 0
    for account_id in sorted(all_account_ids):
        checks = fetch_trusted_advisor_checks(account_id, own_account_id)
        if checks:
            ta_by_account[account_id] = checks
        else:
            ta_errors += 1

    if ta_by_account:
        ta_summaries_by_account, ta_all_summary = summarize_ta_by_account(ta_by_account)
        write_ta_to_s3(ta_summaries_by_account, ta_all_summary)
        logger.info('Trusted Advisor: wrote data for %d accounts (%d skipped)',
                     len(ta_summaries_by_account), ta_errors)
    else:
        logger.warning('Trusted Advisor: no data collected — check support plan / IAM role %s', TA_READER_ROLE_NAME)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'version': AGGREGATOR_VERSION,
            'accountsProcessed': len(summaries),
            'totalFindings': len(findings),
            'taAccountsProcessed': len(ta_by_account),
            'taAccountsSkipped': ta_errors,
        }),
    }
