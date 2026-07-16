"""
Runs on a schedule (EventBridge, e.g. daily 03:00 IST) in the Security Hub
DELEGATED ADMINISTRATOR account.

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

import boto3
import json
import csv
import io
import logging
from datetime import datetime, timezone
from collections import defaultdict
from fpdf import FPDF

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

securityhub = boto3.client('securityhub')
s3 = boto3.client('s3')
sts = boto3.client('sts')

BUCKET = 'securityhub-dashboard-data'

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

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
    """Paginate through GetFindings for ACTIVE, non-suppressed findings."""
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


def summarize_by_account(findings):
    """Group findings by AwsAccountId and compute per-account stats.
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

        penalty = severity_counts['CRITICAL'] * 4 + severity_counts['HIGH'] * 2 + severity_counts['MEDIUM'] * 1
        score = max(0, 100 - min(100, penalty))
        top_controls = sorted(control_counts.values(), key=lambda x: -x['count'])[:5]

        summaries[account_id] = {
            'accountId': account_id,
            'critical': severity_counts['CRITICAL'],
            'high': severity_counts['HIGH'],
            'medium': severity_counts['MEDIUM'],
            'low': severity_counts['LOW'],
            'score': score,
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
    """Builds a summary + full detail PDF for a single account, findings grouped
    and ordered Critical -> High -> Medium -> Low. Returns raw bytes."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, 'AWS Security Hub Compliance Report', ln=True)
    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 8, f'Account: {account_name} ({account_id})', ln=True)
    pdf.cell(0, 8, f'Generated: {summary["lastScan"]}', ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, f'Compliance Score: {summary["score"]}/100', ln=True)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 8,
             f'Critical: {summary["critical"]}   High: {summary["high"]}   '
             f'Medium: {summary["medium"]}   Low: {summary["low"]}',
             ln=True)
    pdf.ln(4)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Top Failing Controls', ln=True)
    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(25, 7, 'Control ID', border=1, fill=True)
    pdf.cell(115, 7, 'Title', border=1, fill=True)
    pdf.cell(25, 7, 'Severity', border=1, fill=True)
    pdf.cell(25, 7, 'Count', border=1, fill=True, ln=True)
    pdf.set_font('Helvetica', '', 9)
    for c in summary.get('topControls', []):
        pdf.cell(25, 7, str(c['id'])[:14], border=1)
        pdf.cell(115, 7, str(c['title'])[:70], border=1)
        pdf.cell(25, 7, str(c['severity']), border=1)
        pdf.cell(25, 7, str(c['count']), border=1, ln=True)
    pdf.ln(6)

    by_severity = defaultdict(list)
    for f in findings:
        sev = f.get('Severity', {}).get('Label', 'LOW')
        by_severity[sev].append(f)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, f'All Findings ({len(findings)} total)', ln=True)
    pdf.ln(1)

    severity_row_colors = {
        'CRITICAL': (245, 220, 220),
        'HIGH': (250, 235, 215),
        'MEDIUM': (255, 250, 210),
        'LOW': (235, 235, 235),
    }

    ordered_severities = SEVERITY_ORDER + [s for s in by_severity if s not in SEVERITY_ORDER]

    for sev in ordered_severities:
        sev_findings = by_severity.get(sev, [])
        if not sev_findings:
            continue

        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 8, f'{sev} ({len(sev_findings)})', ln=True)

        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(60, 7, 'Resource', border=1, fill=True)
        pdf.cell(130, 7, 'Finding Title', border=1, fill=True, ln=True)

        pdf.set_font('Helvetica', '', 8)
        row_color = severity_row_colors.get(sev, (255, 255, 255))
        pdf.set_fill_color(*row_color)
        for f in sev_findings:
            resources = f.get('Resources', [{}])
            resource_id = resources[0].get('Id', 'unknown') if resources else 'unknown'
            title = f.get('Title', 'Unknown finding')
            pdf.cell(60, 6, resource_id[-40:], border=1, fill=True)
            pdf.multi_cell(130, 6, title[:110], border=1, fill=True)
        pdf.ln(4)

    return bytes(pdf.output())


def build_csv_report(account_id, account_name, findings):
    """CSV with one row per finding, sorted Critical -> High -> Medium -> Low."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'AccountId', 'AccountName', 'Severity', 'Title', 'ResourceId',
        'ControlId', 'WorkflowStatus', 'RecordState', 'FirstObservedAt', 'Region',
    ])

    severity_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_rank.get(f.get('Severity', {}).get('Label', 'LOW'), 99)
    )

    for f in sorted_findings:
        sev = f.get('Severity', {}).get('Label', 'LOW')
        title = f.get('Title', 'Unknown finding')
        resources = f.get('Resources', [{}])
        resource_id = resources[0].get('Id', 'unknown') if resources else 'unknown'
        control_id = f.get('ProductFields', {}).get('ControlId') or f.get('GeneratorId', 'UNKNOWN')
        workflow_status = f.get('Workflow', {}).get('Status', 'UNKNOWN')
        record_state = f.get('RecordState', 'UNKNOWN')
        first_observed = f.get('FirstObservedAt', '')
        region = f.get('Region', '')

        writer.writerow([
            account_id, account_name, sev, title, resource_id,
            control_id, workflow_status, record_state, first_observed, region,
        ])

    return output.getvalue().encode('utf-8')


def generate_and_upload_reports(summaries, by_account, account_names):
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
        'score': round(sum(s['score'] for s in summaries.values()) / max(1, len(summaries))),
        'lastScan': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'topControls': [],
    }
    pdf_bytes = build_pdf_report('ALL', 'All Accounts', all_summary, all_findings)
    s3.put_object(Bucket=BUCKET, Key='reports/all/latest.pdf',
                   Body=pdf_bytes, ContentType='application/pdf')

    csv_bytes = build_csv_report('ALL', 'All Accounts', all_findings)
    s3.put_object(Bucket=BUCKET, Key='reports/all/latest.csv',
                   Body=csv_bytes, ContentType='text/csv')


def write_to_s3(summaries, by_account, account_names):
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
        'score': round(sum(s['score'] for s in summaries.values()) / max(1, len(summaries))),
        'lastScan': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'topControls': [],
    }
    s3.put_object(Bucket=BUCKET, Key='summaries/all/latest.json',
                   Body=json.dumps(all_summary), ContentType='application/json')

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

    # --- Security Hub ---
    findings = fetch_all_findings()
    summaries, by_account = summarize_by_account(findings)
    write_to_s3(summaries, by_account, account_names)
    generate_and_upload_reports(summaries, by_account, account_names)
    logger.info('Security Hub: wrote summaries/reports for %d accounts', len(summaries))

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
            'accountsProcessed': len(summaries),
            'totalFindings': len(findings),
            'taAccountsProcessed': len(ta_by_account),
            'taAccountsSkipped': ta_errors,
        }),
    }
