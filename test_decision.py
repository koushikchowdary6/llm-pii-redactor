import json
from pathlib import Path
import tempfile
import unittest

from decision import decide, export_approved
from review import build


class ReviewDecisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        source = root / 'input.txt'
        source.write_text('Contact demo@example.com about the case.', encoding='utf-8')
        self.bundle = root / 'bundle'
        build(source, self.bundle)
        self.destination = root / 'released.txt'

    def approve(self):
        return decide(self.bundle, 'approved', 'demo reviewer', 'Inspected sanitized text')

    def test_pending_bundle_cannot_be_exported(self):
        with self.assertRaises(FileNotFoundError):
            export_approved(self.bundle, self.destination)
        self.assertFalse(self.destination.exists())

    def test_approved_bundle_exports_only_sanitized_text(self):
        record = self.approve()
        self.assertEqual(record['status'], 'approved')
        export_approved(self.bundle, self.destination)
        output = self.destination.read_text(encoding='utf-8')
        self.assertEqual(output, (self.bundle / 'sanitized.txt').read_text())
        self.assertNotIn('demo@example.com', output)

    def test_rejected_bundle_cannot_be_exported(self):
        decide(self.bundle, 'rejected', 'demo reviewer', 'Needs further redaction')
        with self.assertRaises(ValueError):
            export_approved(self.bundle, self.destination)
        self.assertFalse(self.destination.exists())

    def test_tamper_before_review_prevents_decision(self):
        (self.bundle / 'sanitized.txt').write_text('modified')
        with self.assertRaises(ValueError):
            self.approve()
        self.assertFalse((self.bundle / 'decision.json').exists())

    def test_tamper_after_approval_prevents_export(self):
        self.approve()
        (self.bundle / 'sanitized.txt').write_text('modified')
        with self.assertRaises(ValueError):
            export_approved(self.bundle, self.destination)
        self.assertFalse(self.destination.exists())

    def test_tamper_decision_digest_prevents_export(self):
        self.approve()
        decision_path = self.bundle / 'decision.json'
        decision = json.loads(decision_path.read_text())
        decision['sanitized_sha256'] = '0' * 64
        decision_path.write_text(json.dumps(decision))
        with self.assertRaises(ValueError):
            export_approved(self.bundle, self.destination)

    def test_review_decision_cannot_be_overwritten(self):
        self.approve()
        with self.assertRaises(FileExistsError):
            decide(self.bundle, 'rejected', 'other reviewer', 'Changed mind')
        self.assertEqual(json.loads((self.bundle / 'decision.json').read_text())['status'], 'approved')

    def test_existing_export_cannot_be_overwritten(self):
        self.approve()
        self.destination.write_text('existing')
        with self.assertRaises(FileExistsError):
            export_approved(self.bundle, self.destination)
        self.assertEqual(self.destination.read_text(), 'existing')

    def test_reviewer_and_rationale_are_required(self):
        with self.assertRaises(ValueError):
            decide(self.bundle, 'approved', ' ', 'reason')
        with self.assertRaises(ValueError):
            decide(self.bundle, 'approved', 'reviewer', ' ')
        self.assertFalse((self.bundle / 'decision.json').exists())

    def test_manifest_must_remain_pending(self):
        manifest_path = self.bundle / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['review_required'] = False
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.approve()


if __name__ == '__main__':
    unittest.main()
