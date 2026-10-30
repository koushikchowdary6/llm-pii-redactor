# Document Review — redaction bundles for ingestion workflows

A local document-ingestion stage that applies the repository's real redactor
to UTF-8 text, writes sanitized content, and attaches a review manifest. This
implements the text-review portion of an OCR/document-processing architecture;
OCR and PDF pixel masking are not implemented or claimed.

## Run

From the repository root, Python 3.10+ with no third-party dependencies:

```bash
python projects/document-review/review.py projects/document-review/examples/synthetic.txt /tmp/review-bundle
cat /tmp/review-bundle/sanitized.txt
cat /tmp/review-bundle/manifest.json
python -m unittest discover -s projects/document-review -v
```

Choose a new destination for each run. Existing directories are rejected.
The synthetic fixture contains an email and SSN for a reproducible demonstration.
No client or patient documents are included.

## What happens

1. Read at most the redactor's character budget plus one; reject oversized input.
2. Detect and redact using `src/redactor.py`, without making external API calls.
3. Record types, offsets, counts and content fingerprints; omit raw matches and
   source filenames from the manifest.
4. Stage both files in a private directory and rename it into place.
5. Mark every bundle `pending_manual_review`, including zero-finding documents.

Offsets refer to the original text, not the redacted output. SHA-256 digests
identify content but do not encrypt it or prevent guessing predictable inputs.
The bundle directory is mode 0700 on POSIX systems. The rename publishes both
files together on the same filesystem, but is not a power-loss durability
promise. This CLI assumes one writer per destination.

## Review procedure

Inspect sanitized text before downstream indexing. Pattern detection can miss
names and contextual identifiers. Review decisions are manual; this tool does
not contain an approval UI or authorize release. Never feed the original file
to a downstream model when this stage fails. Use synthetic data for demos.

## Validation and scope

Four tests check raw-email absence from bundle files, overwrite rejection,
budget rejection without partial output, and required review for missed names.
No OCR accuracy, PHI recall, HIPAA compliance, model performance or production
throughput is claimed. A future OCR adapter must preserve page coordinates and
validate final rendered pixel masking separately from text redaction.

## Interview walkthrough

Run the fixture; inspect the sanitized output and metadata. Then try a sentence
with an ordinary person's name to show why a zero-finding report is not proof
of de-identification. Explain the trust boundary before retrieval indexing and
why audit logs should not copy the secrets the system just removed.
