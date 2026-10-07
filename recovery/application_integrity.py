"""Preserve pre-experiment artifacts and the exact existing flow split."""
import hashlib
import json
from pathlib import Path
import subprocess

from recovery.application_audit import OUT, read
from recovery.capture_audit import sha


def verify(include_graphs=False):
    before = read(OUT / 'integrity_before.json')
    captures = {p: sha(Path(before['capture_root']) / p) for p in before['capture_sha256_before']}
    if captures != before['capture_sha256_before']:
        raise ValueError('STOP L: original source capture changed')
    for p, expected in before['preserved_files_sha256'].items():
        if sha(p) != expected:
            raise ValueError(f'Preserved pre-experiment artifact changed: {p}')
    if sha(before['split_manifest']) != before['split_sha256']:
        raise ValueError('STOP K: original flow-disjoint split changed')
    if sha(before['archive']) != before['archive_sha256']:
        raise ValueError('Original archive changed')
    branches = {**before['backup_branches'], 'backup/pre-application-ciphertext-20261008': before['starting_commit']}
    for branch, expected in branches.items():
        if subprocess.check_output(['git', 'rev-parse', branch], text=True).strip() != expected:
            raise ValueError(f'Backup branch changed: {branch}')
    cache_checks = {}
    if include_graphs:
        for name, expected in before['graph_cache_sha256_before'].items():
            rows = [[p.name, sha(p)] for p in sorted((Path('data/recovery/graphs') / name).glob('*.pt'))]
            digest = hashlib.sha256(json.dumps(rows).encode()).hexdigest()
            if len(rows) != 1674 or digest != expected:
                raise ValueError(f'Original graph cache changed: {name}')
            cache_checks[name] = dict(files=len(rows), sha256=digest)
    return dict(passed=True, captures=len(captures), capture_sha256=captures,
                preserved_previous_tracked_files=len(before['preserved_files_sha256']),
                split_sha256=before['split_sha256'], original_backups_and_archive_preserved=True,
                original_graph_caches=cache_checks)
