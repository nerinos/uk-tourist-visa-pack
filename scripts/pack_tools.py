#!/usr/bin/env python3
"""Inventory originals and verify/package a manifest-defined PDF upload tree."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import zipfile

from pypdf import PdfReader

EXTENSIONS = {'.pdf', '.docx', '.jpg', '.jpeg', '.png', '.tif', '.tiff',
              '.webp', '.bmp', '.gif', '.heic', '.heif'}
STATUSES = {'ready', 'accepted_exception', 'needs_review'}
SHA = re.compile(r'[0-9a-f]{64}\Z')


def absolute(value):
    return Path(os.path.abspath(os.path.expanduser(str(value))))


def linked(path):
    return any(p.is_symlink() for p in (path, *path.parents))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pdf_info(path, extract=False):
    result = {'pages': None, 'encrypted': None, 'read_error': None}
    if extract:
        result.update(page_char_counts=[], text_extraction_errors=[])
    try:
        with path.open('rb') as stream:
            reader = PdfReader(stream, strict=True)
            result['encrypted'] = reader.is_encrypted
            if reader.is_encrypted:
                return result
            result['pages'] = len(reader.pages)
            for index, page in enumerate(reader.pages):
                # Parse page content streams without interpreting scan quality.
                contents = page.get_contents()
                if contents is not None:
                    contents.get_data()
                if extract:
                    try:
                        result['page_char_counts'].append(len(page.extract_text() or ''))
                    except Exception as exc:
                        result['page_char_counts'].append(None)
                        result['text_extraction_errors'].append({'page': index + 1, 'error': str(exc)})
    except Exception as exc:
        result['read_error'] = str(exc)
    return result


def walk(root, excluded=()):
    files, issues = [], []
    def skip(path):
        return any(path == item or item in path.parents for item in excluded)
    def inspect(path):
        if skip(path):
            return False
        if path.is_symlink():
            issues.append(f'Symlink skipped: {path}')
            return False
        return True
    if skip(root):
        return files, issues
    if linked(root):
        return files, [f'Symlink in source path: {root}']
    if root.is_file():
        return [root], issues
    if not root.is_dir():
        return files, [f'Missing or unsupported source: {root}']
    for parent, dirs, names in os.walk(root, followlinks=False, onerror=lambda exc: issues.append(str(exc))):
        base = Path(parent)
        dirs[:] = sorted(name for name in dirs if inspect(base / name))
        files.extend(base / name for name in sorted(names) if inspect(base / name))
    return files, issues


def protect_outputs(outputs, root, protected):
    seen = set()
    for output in outputs:
        if linked(output) or output.is_dir():
            raise ValueError(f'Output is a directory or uses a symlink: {output}')
        if any(parent.exists() and not parent.is_dir() for parent in output.parents):
            raise ValueError(f'Output parent is not a directory: {output}')
        if output == root or root in output.parents or (root.exists() and any(parent.exists() and os.path.samefile(parent, root) for parent in output.parents)):
            raise ValueError(f'Output must be outside upload root: {output}')
        if any(str(output).casefold() == str(other).casefold() or output in other.parents or other in output.parents for other in seen):
            raise ValueError(f'Output paths collide: {output}')
        for source in [*protected, *seen]:
            if output == source or (output.exists() and source.exists() and os.path.samefile(output, source)):
                raise ValueError(f'Output would overwrite an input or another output: {output}')
        seen.add(output)


def atomic(path, writer):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        writer(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value):
    atomic(path, lambda temporary: temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'))


def inventory(args):
    output = absolute(args.output)
    if output.exists() and output.suffix.lower() in EXTENSIONS:
        raise ValueError('Inventory output cannot replace an existing source document')
    excluded = [output, *(absolute(item) for group in args.exclude for item in group)]
    paths, issues = set(), []
    for source in args.sources:
        found, errors = walk(absolute(source), excluded)
        paths.update(path for path in found if path.is_file() and path.suffix.lower() in EXTENSIONS)
        issues.extend(errors)
    # A discovered source must never be overwritten, including hard-link aliases.
    protect_outputs([output], output / '__not_an_upload_root__', [*paths, *(absolute(item) for item in args.sources)])
    rows, hashes = [], {}
    for path in sorted(paths):
        row = {'name': path.name, 'path': str(path), 'bytes': None, 'sha256': None}
        try:
            row.update(bytes=path.stat().st_size, sha256=digest(path))
            hashes.setdefault(row['sha256'], []).append(str(path))
            if path.suffix.lower() == '.pdf':
                row['pdf'] = pdf_info(path, extract=True)
        except Exception as exc:
            row['read_error'] = str(exc)
        rows.append(row)
    write_json(output, {'files': rows, 'exact_hash_duplicates': [value for _, value in sorted(hashes.items()) if len(value) > 1],
                        'issues': sorted(set(issues)), 'content_completeness': 'not_assessed'})
    return 0


def safe_component(value):
    return (isinstance(value, str) and bool(value) and not value.startswith('.')
            and value == value.strip() and not value.endswith('.')
            and not re.search(r'[\x00-\x1f\x7f/\\:<>"|?*]', value)
            and value.split('.')[0].upper() not in {'CON', 'PRN', 'AUX', 'NUL',
                *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))})


def check_hash(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def make_zip(target, root, categories, rows):
    expected = {f'{root.name}/': None}
    expected.update({f'{root.name}/{folder}/': None for folder in categories})
    expected.update({f'{root.name}/{row["path"]}': row['expected_sha256'] for row in rows})
    def build(temporary):
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, expected_hash in sorted(expected.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = ((0o40755 if expected_hash is None else 0o100644) << 16)
                entry.compress_type = zipfile.ZIP_DEFLATED
                data = b'' if expected_hash is None else (root / name[len(root.name) + 1:]).read_bytes()
                if expected_hash is not None and hashlib.sha256(data).hexdigest() != expected_hash:
                    raise ValueError(f'Input changed before packaging: {name}')
                archive.writestr(entry, data)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None or sorted(archive.namelist()) != sorted(expected):
                raise ValueError('ZIP CRC or entry-set verification failed')
            for name, expected_hash in expected.items():
                if expected_hash is not None and hashlib.sha256(archive.read(name)).hexdigest() != expected_hash:
                    raise ValueError(f'ZIP hash mismatch: {name}')
    atomic(target, build)


def verify(args):
    root, manifest_path, report_path = map(absolute, (args.root, args.manifest, args.report))
    csv_path, zip_path = (absolute(args.csv) if args.csv else None), (absolute(args.zip) if args.zip else None)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if not isinstance(manifest, dict):
        raise ValueError('Manifest must be a JSON object')
    entries = manifest.get('files')
    protected = [manifest_path]
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get('sources'), list):
                protected.extend(absolute(source['path']) for source in entry['sources']
                                 if isinstance(source, dict) and isinstance(source.get('path'), str))
    actual, errors = walk(root)
    protect_outputs([path for path in (report_path, csv_path, zip_path) if path], root, [*protected, *actual])
    if not root.is_dir() or linked(root) or not safe_component(root.name):
        errors.append('Upload root must be an existing directory with a safe name and no symlinks')
    limit, strict = manifest.get('max_file_bytes'), manifest.get('strictly_less_than_limit')
    if type(limit) is not int or limit <= 0 or type(strict) is not bool:
        errors.append('Require positive integer max_file_bytes and boolean strictly_less_than_limit')
    categories = {}
    category_entries = manifest.get('categories')
    if not isinstance(category_entries, list) or not category_entries:
        errors.append('categories must be a nonempty list')
    else:
        for category in category_entries:
            folder = category.get('folder') if isinstance(category, dict) else None
            label = category.get('portal_label') if isinstance(category, dict) else None
            if not safe_component(folder) or not isinstance(label, str) or not label.strip():
                errors.append('Each category needs a safe folder and nonempty portal_label')
            elif folder.casefold() in {key.casefold() for key in categories}:
                errors.append(f'Duplicate category: {folder}')
            else:
                categories[folder] = label
                if not (root / folder).is_dir() or linked(root / folder):
                    errors.append(f'Category directory missing or uses symlinks: {folder}')
    rows, declared = [], set()
    if not isinstance(entries, list) or not entries:
        errors.append('files must be a nonempty list')
        entries = []
    for entry in entries:
        row = {'path': entry.get('path') if isinstance(entry, dict) else None, 'bytes': None,
               'sha256': None, 'expected_sha256': None, 'category': None, 'portal_label': None,
               'status': None, 'note': '', 'applicant_id': '', 'errors': []}
        rows.append(row)
        if not isinstance(entry, dict):
            row['errors'].append('File entry must be an object')
            continue
        row.update({key: entry.get(key, '') for key in ('status', 'note', 'applicant_id')})
        row['expected_sha256'] = entry.get('sha256')
        if not isinstance(row['status'], str) or row['status'] not in STATUSES or any(not isinstance(row[key], str) for key in ('note', 'applicant_id')):
            row['errors'].append('Invalid status, note, or applicant_id')
        if not check_hash(row['expected_sha256']):
            row['errors'].append('Output sha256 must be 64 lowercase hexadecimal characters')
        name = row['path']
        parts = name.split('/') if isinstance(name, str) else []
        if len(parts) != 2 or not all(safe_component(part) for part in parts) or PurePosixPath(name).suffix.lower() != '.pdf' or parts[0] not in categories:
            row['errors'].append('Path must be a safe declared-category/filename.pdf relative path')
            continue
        row.update(category=parts[0], portal_label=categories[parts[0]])
        if name.casefold() in {item.casefold() for item in declared}:
            row['errors'].append('Duplicate manifest path')
        declared.add(name)
        path = root / name
        try:
            if linked(path) or not path.is_file():
                raise ValueError('Missing PDF or symlink in PDF path')
            row.update(bytes=path.stat().st_size, sha256=digest(path), pdf=pdf_info(path))
            if row['sha256'] != row['expected_sha256']:
                row['errors'].append('Output hash mismatch')
            if type(limit) is int and limit > 0 and type(strict) is bool and (row['bytes'] >= limit if strict else row['bytes'] > limit):
                row['errors'].append('File exceeds declared byte limit')
            if row['pdf']['encrypted'] or row['pdf']['read_error'] or not row['pdf']['pages']:
                row['errors'].append('PDF must be readable, unencrypted, and have at least one page')
        except Exception as exc:
            row['errors'].append(str(exc))
        sources = entry.get('sources', [])
        if not isinstance(sources, list):
            row['errors'].append('sources must be a list')
            sources = []
        row['source_checks'] = []
        for source in sources:
            check = {'path': source.get('path') if isinstance(source, dict) else None, 'ok': False}
            try:
                if not isinstance(source, dict) or not isinstance(source.get('path'), str) or not Path(source['path']).is_absolute() or not check_hash(source.get('sha256')):
                    raise ValueError('Each source needs an absolute path and lowercase sha256')
                original = absolute(source['path'])
                if linked(original) or not original.is_file() or digest(original) != source['sha256']:
                    raise ValueError('Source missing, uses symlink, or hash mismatch')
                check['ok'] = True
            except Exception as exc:
                check['error'] = str(exc)
                row['errors'].append(f'Source check failed: {check["path"]}: {exc}')
            row['source_checks'].append(check)
    found = {path.relative_to(root).as_posix() for path in actual if path.suffix.lower() == '.pdf'}
    errors.extend(f'Unexpected upload PDF: {name}' for name in sorted(found - declared))
    errors.extend(f'Missing upload PDF: {name}' for name in sorted(declared - found))
    for name in sorted(found - declared):
        row = {'path': name, 'bytes': None, 'sha256': None, 'expected_sha256': None,
               'category': name.split('/')[0] if '/' in name else '', 'status': 'unlisted',
               'note': '', 'applicant_id': '', 'errors': ['Unexpected upload PDF']}
        row['portal_label'] = categories.get(row['category'], '')
        try:
            path = root / name
            if not path.is_file():
                raise ValueError('Not a regular file')
            row.update(bytes=path.stat().st_size, sha256=digest(path), pdf=pdf_info(path))
        except Exception as exc:
            row['errors'].append(str(exc))
        rows.append(row)
    passed = not errors and not any(row['errors'] for row in rows)
    packaging = 'not_requested' if not zip_path else 'refused'
    if zip_path and passed:
        try:
            make_zip(zip_path, root, categories, rows)
            packaging = 'verified'
        except Exception as exc:
            errors.append(f'Packaging failed: {exc}')
            passed = False
    report = {'technical_checks': 'passed' if passed else 'failed', 'content_completeness': 'not_assessed',
              'content_status_counts': {status: sum(row['status'] == status for row in rows) for status in sorted(STATUSES)},
              'packaging': packaging, 'errors': errors, 'files': rows}
    if csv_path:
        stream = io.StringIO(newline='')
        writer = csv.writer(stream)
        writer.writerow(['path', 'bytes', 'sha256', 'category', 'portal_label', 'status', 'applicant_id', 'note', 'technical_checks', 'errors'])
        for row in rows:
            writer.writerow([row[key] for key in ('path', 'bytes', 'sha256', 'category', 'portal_label', 'status', 'applicant_id', 'note')]
                            + ['failed' if row['errors'] else 'passed', '; '.join(row['errors'])])
        atomic(csv_path, lambda temporary: temporary.write_text(stream.getvalue(), encoding='utf-8'))
    write_json(report_path, report)
    print(json.dumps({'technical_checks': report['technical_checks'], 'packaging': packaging,
                      'content_status_counts': report['content_status_counts'], 'report': str(report_path)}))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inv = commands.add_parser('inventory')
    inv.add_argument('sources', metavar='SOURCE', nargs='+')
    inv.add_argument('--output', required=True)
    inv.add_argument('--exclude', nargs='+', action='append', default=[])
    check = commands.add_parser('verify')
    for flag in ('root', 'manifest', 'report'):
        check.add_argument(f'--{flag}', required=True)
    check.add_argument('--csv')
    check.add_argument('--zip')
    args = parser.parse_args()
    try:
        return inventory(args) if args.command == 'inventory' else verify(args)
    except (OSError, ValueError, TypeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
