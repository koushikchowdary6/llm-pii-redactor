import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from review import build

class Tests(unittest.TestCase):
    def test_bundle_has_no_raw_email(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'input.txt'; source.write_text('Contact demo@example.com')
            out=Path(d)/'bundle'; report=build(source,out)
            self.assertTrue(report['review_required'])
            self.assertEqual(report['finding_counts']['EMAIL'],1)
            for file in out.iterdir(): self.assertNotIn('demo@example.com',file.read_text())
            self.assertEqual(json.loads((out/'manifest.json').read_text())['status'],'pending_manual_review')
    def test_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'in'; source.write_text('test')
            out=Path(d)/'bundle'; build(source,out)
            with self.assertRaises(ValueError): build(source,out)
    def test_budget_leaves_no_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'in'; source.write_text('12345')
            out=Path(d)/'bundle'
            with patch('review.MAX_INPUT_CHARS',4), self.assertRaises(ValueError): build(source,out)
            self.assertFalse(out.exists())
    def test_contextual_pii_still_requires_review(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'in'; source.write_text('Patient Alice visits on Tuesday.')
            out=Path(d)/'bundle'; result=build(source,out)
            self.assertTrue(result['review_required'])
            self.assertIn('Alice',(out/'sanitized.txt').read_text())

if __name__ == '__main__': unittest.main()
