"""Publish a review bundle from text extracted upstream from documents."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from redactor import MAX_INPUT_CHARS, redact


def build(source, destination):
    source, destination = Path(source), Path(destination)
    if destination.exists():
        raise ValueError('Destination exists; choose a new review bundle directory')
    with source.open(encoding='utf-8') as stream:
        text = stream.read(MAX_INPUT_CHARS + 1)
    if len(text) > MAX_INPUT_CHARS:
        raise ValueError('Input exceeds budget')
    sanitized, findings = redact(text)
    manifest = {
        'schema_version': 1,
        'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
        'sanitized_sha256': hashlib.sha256(sanitized.encode()).hexdigest(),
        'characters': len(text),
        'finding_counts': dict(Counter(f.kind for f in findings)),
        'findings': [{'kind': f.kind, 'start': f.start, 'end': f.end} for f in findings],
        'review_required': True,
        'status': 'pending_manual_review',
        'scope': 'Pattern-based text redaction; no OCR, no PDF pixel masking, no compliance certification',
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.review-', dir=destination.parent))
    try:
        os.chmod(stage, 0o700)
        (stage / 'sanitized.txt').write_text(sanitized, encoding='utf-8')
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        # Both files become visible as a bundle. Intended for a single local writer.
        stage.rename(destination)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('destination', type=Path)
    a = p.parse_args()
    try:
        result = build(a.source, a.destination)
    except (ValueError, OSError, UnicodeError):
        p.exit(1, 'Review bundle not created. Check input, size budget, and destination.\n')
    print(json.dumps({'status': result['status'], 'finding_counts': result['finding_counts']}))
