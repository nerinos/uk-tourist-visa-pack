# Local inventory and verification

`scripts/pack_tools.py` uses Python 3.11+ and `pypdf`. It reads originals; it never
converts, edits, decrypts, renames, or deletes them. Install the dependency in the
chosen Python environment (`python -m pip install pypdf`) if needed.

```sh
python scripts/pack_tools.py inventory originals extra-source.pdf \
  --output work/inventory.json --exclude originals/prepared originals/backup
python scripts/pack_tools.py verify --root work/UPLOAD \
  --manifest work/manifest.json --report work/verification.json \
  --csv work/index.csv --zip work/upload.zip
```

Inventory recursively collects PDF, DOCX, JPG/JPEG, PNG, TIFF, WebP, BMP, GIF,
HEIC, and HEIF files, without following symlinks. It excludes its output and
explicitly excluded paths, records bytes and SHA-256, and groups exact hash
duplicates. PDF metadata includes page count, encryption, per-page extracted
character counts, and read/extraction errors. Zero characters can mean a scan;
neither text counts nor filenames establish document completeness. Inventory
issues and read errors require review even when the command exits successfully.

Manifest example (replace hashes and source path with actual inventory values):

```json
{
  "max_file_bytes": 5000000,
  "strictly_less_than_limit": true,
  "categories": [
    {"folder": "Other", "portal_label": "Other"},
    {"folder": "Financial Evidence", "portal_label": "Financial Evidence"}
  ],
  "files": [{
    "path": "Other/01-document.pdf",
    "sha256": "<64 lowercase hexadecimal characters>",
    "sources": [{
      "path": "<absolute original file path>",
      "sha256": "<64 lowercase hexadecimal characters>"
    }],
    "status": "needs_review",
    "note": "Check the visible pages against the document checklist.",
    "applicant_id": "applicant-1"
  }]
}
```

Each category directory must exist, including empty categories. Paths must be
exactly `declared-category/filename.pdf`, use `/`, and contain no hidden names,
traversal, absolute paths, symlinks, unsafe portable filename characters, or
case-insensitive duplicates. Output hashes are mandatory. `sources` is optional;
every supplied source must exist, be a regular file without symlink components,
and match its hash. `note` and `applicant_id` are optional strings. Status is
mandatory and must be `ready`, `accepted_exception`, or `needs_review`.

Verification checks the exact upload PDF set, SHA-256, readable nonencrypted
PDFs with at least one page, and the declared byte limit. `true` means strictly
less than the limit; `false` permits equality. Any technical failure refuses
packaging. Content status is reported separately: `needs_review` and
`accepted_exception` do not become assertions of legal or semantic completeness,
and they do not by themselves prevent creating a technically verified ZIP.

The report and CSV contain each manifest file's actual byte size, checks,
category, and content status. Unexpected PDFs also get rows with `unlisted`
status and appear as report-level errors.
Report, CSV, and ZIP must be distinct paths outside the upload root and must
not overwrite the manifest, originals, upload files, or their hard-link aliases.
Malformed JSON or unsafe output destinations abort without a new report. Other
validation failures produce a report and optional CSV. Exit codes: `0` for
successful inventory / passed technical verification; `1` for failed verification;
`2` for command/input/output errors. Always read the report and content statuses.

ZIP contains only manifest PDFs below `UPLOAD/` (the actual root basename),
plus declared category directories including empty ones. Notes, hidden files,
the manifest, and indexes are excluded. Entries use fixed timestamps and sorted
names. CRC and every PDF entry hash are checked before atomic replacement;
report and CSV also use temporary files and atomic replacement. A failed check
does not remove or replace an existing ZIP, so never mistake an older archive
for the latest result. This is a local technical check, not a PDF renderer,
malware scanner, OCR engine, or assessment of legal sufficiency.
