"""Round-trip CSV parsing. Identity always includes run, CVE and package."""
import csv
import io
from fastapi import HTTPException

COLUMNS = ['Run ID', 'Image', 'CVE ID', 'Package', 'Version', 'Fixed In', 'CVSS', 'Severity', 'Status',
           'Justification', 'Remediation', 'Manual Notes']


def cell(value):
    value = str(value or '')
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@', "'", '\t', '\r')) else value


def export(rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(COLUMNS)
    for run, cve in rows:
        writer.writerow([cell(v) for v in [run['run_id'], run['image_ref'], cve['id'], cve['pkg'],
            cve.get('version'), cve.get('fixed_in'), cve.get('cvss'), cve.get('severity'), cve['status'], cve.get('rationale'),
            cve.get('remediation'), cve.get('manual_notes')]])
    return output.getvalue()


def parse(content):
    if len(content.encode('utf-8')) > 5_000_000:
        raise HTTPException(422, 'CSV must be at most 5 MB')
    try:
        reader = csv.DictReader(io.StringIO(content.lstrip('\ufeff')), strict=True)
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames) or not set(COLUMNS).issubset(reader.fieldnames):
            raise ValueError('Use the downloaded project CSV or template; all template headers are required')
        rows = []
        seen = set()
        for number, row in enumerate(reader, 2):
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f'Row {number}: incorrect number of columns')
            row = {k: v[1:] if v.startswith("'") else v for k, v in row.items()}
            key = (row['Run ID'], row['CVE ID'], row['Package'])
            if not all(key) or key in seen:
                raise ValueError(f'Row {number}: missing or duplicate finding identity')
            if row['Status'] not in ('queued', 'pending', 'submitted', 'approved', 'rejected'):
                raise ValueError(f'Row {number}: invalid Status')
            seen.add(key)
            rows.append(row)
            if len(rows) > 20_000:
                raise ValueError('CSV may contain at most 20,000 findings')
        if not rows:
            raise ValueError('CSV has no findings')
        return rows
    except (ValueError, csv.Error) as error:
        raise HTTPException(422, str(error)) from error
