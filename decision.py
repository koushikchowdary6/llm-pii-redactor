"""Local manual-review decision and fail-closed sanitized-text export.

This is an auditable local workflow, not authenticated identity, a signature,
or a regulatory compliance system. A reviewer must inspect the text manually.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


def verify_bundle(bundle):
    bundle = Path(bundle)
    manifest = json.loads((bundle / 'manifest.json').read_text(encoding='utf-8'))
    if (not isinstance(manifest, dict) or manifest.get('schema_version') != 1
            or manifest.get('status') != 'pending_manual_review'
            or manifest.get('review_required') is not True):
        raise ValueError('Invalid or non-pending review manifest')
    sanitized = (bundle / 'sanitized.txt').read_text(encoding='utf-8')
    digest = hashlib.sha256(sanitized.encode('utf-8')).hexdigest()
    if manifest.get('sanitized_sha256') != digest:
        raise ValueError('Sanitized text differs from review manifest')
    return manifest, sanitized


def _write_exclusive(path, content):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def decide(bundle, status, reviewer, rationale):
    if status not in ('approved', 'rejected'):
        raise ValueError('Decision must be approved or rejected')
    if not isinstance(reviewer, str) or not 1 <= len(reviewer.strip()) <= 128:
        raise ValueError('Reviewer must be 1..128 characters')
    if not isinstance(rationale, str) or not 1 <= len(rationale.strip()) <= 2000:
        raise ValueError('Rationale must be 1..2000 characters')
    manifest, _ = verify_bundle(bundle)
    record = {
        'schema_version': 1,
        'status': status,
        'reviewer': reviewer.strip(),
        'rationale': rationale.strip(),
        'reviewed_at_utc': datetime.now(timezone.utc).isoformat(),
        'sanitized_sha256': manifest['sanitized_sha256'],
    }
    _write_exclusive(Path(bundle) / 'decision.json', json.dumps(record, indent=2) + '\n')
    return record


def export_approved(bundle, destination):
    manifest, sanitized = verify_bundle(bundle)
    decision = json.loads((Path(bundle) / 'decision.json').read_text(encoding='utf-8'))
    if (not isinstance(decision, dict) or decision.get('schema_version') != 1
            or decision.get('status') != 'approved'
            or decision.get('sanitized_sha256') != manifest['sanitized_sha256']
            or not isinstance(decision.get('reviewer'), str)
            or not decision['reviewer'].strip()
            or not isinstance(decision.get('rationale'), str)
            or not decision['rationale'].strip()):
        raise ValueError('Approved review decision missing or inconsistent')
    destination = Path(destination)
    _write_exclusive(destination, sanitized)
    return destination


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    review = commands.add_parser('decide', help='Record one manual decision per bundle')
    review.add_argument('bundle', type=Path)
    review.add_argument('--status', choices=('approved', 'rejected'), required=True)
    review.add_argument('--reviewer', required=True)
    review.add_argument('--rationale', required=True)
    release = commands.add_parser('export', help='Export sanitized text only after approval')
    release.add_argument('bundle', type=Path)
    release.add_argument('destination', type=Path)
    args = p.parse_args()
    try:
        if args.command == 'decide':
            record = decide(args.bundle, args.status, args.reviewer, args.rationale)
            print(json.dumps({'status': record['status']}))
        else:
            export_approved(args.bundle, args.destination)
            print(json.dumps({'status': 'exported'}))
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError):
        p.exit(1, 'Review operation rejected; check bundle integrity, decision and destination.\n')
