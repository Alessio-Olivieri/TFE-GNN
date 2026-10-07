"""Publish feasibility STOP reports without inventing splits or ciphertext coverage.

New project analysis infrastructure; no model, source-data or graph mutations.
Run after recovery.capture_audit, then recovery.validate_capture_audit.
"""
import collections
import csv
import datetime
import importlib.metadata
import itertools
import json
from pathlib import Path
import subprocess
import sys

from recovery.audit import CLASSES, packets
from recovery.capture_audit import (OUT, CIPHER_OUT, SOURCES, csv_save, save, load_samples,
                                    refine_capture_groups, assess_feasibility, sha)


def read(path):
    return json.loads(Path(path).read_text())


def text_save(path, text):
    with Path(path).open('x') as handle:
        handle.write(text.rstrip() + '\n')


def table(columns, rows):
    return '\n'.join(['| ' + ' | '.join(columns) + ' |',
                      '| ' + ' | '.join(['---'] * len(columns)) + ' |',
                      *['| ' + ' | '.join(map(str, row)) + ' |' for row in rows]])


def ipv6_transport(data):
    """Only for counting excluded IPv6 traffic; never used for model extraction."""
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    nxt, off = data[6], 40
    for _ in range(16):
        if nxt not in (0, 43, 44, 51, 60):
            return nxt
        if off + 8 > len(data):
            return None
        if nxt == 44:
            # Non-initial fragments cannot establish transport packet structure.
            if int.from_bytes(data[off + 2:off + 4], 'big') & 0xfff8:
                return None
            size = 8
        else:
            size = (data[off + 1] + (2 if nxt == 51 else 1)) * (4 if nxt == 51 else 8)
        nxt, off = data[off], off + size
    return None


def supplemental_scope(captures, capture_root):
    """Disambiguate outer IPv6 and OpenVPN labels inside ICMP quotations."""
    rows, observations = [], []
    for c in captures:
        counts = c['stage_counts']
        ipv6 = collections.Counter()
        if c['protocol_dissector']['raw_packet_protocol_labels'].get('ipv6', 0):
            for _, link, raw, _ in packets(Path(capture_root) / c['source_pcap']):
                if link != 1 or len(raw) < 54 or raw[12:14] != b'\x86\xdd':
                    continue
                proto = ipv6_transport(raw[14:])
                ipv6['packets'] += 1
                ipv6['tcp' if proto == 6 else 'udp' if proto == 17 else 'other'] += 1
        row = dict(source_capture=c['source_pcap'], class_label=c['labels'][0],
                   raw_packets=counts['raw_packets'], raw_ipv4_tcp_packets=counts.get('raw_tcp_packets', 0),
                   raw_ipv4_udp_packets=counts.get('raw_udp_packets', 0),
                   raw_ipv6_tcp_packets=ipv6['tcp'], raw_ipv6_udp_packets=ipv6['udp'],
                   raw_ipv6_other_packets=ipv6['other'], raw_ipv6_packets=ipv6['packets'])
        row['raw_outer_tcp_packets'] = row['raw_ipv4_tcp_packets'] + row['raw_ipv6_tcp_packets']
        row['raw_outer_udp_packets'] = row['raw_ipv4_udp_packets'] + row['raw_ipv6_udp_packets']
        row['raw_outer_other_packets'] = row['raw_packets'] - row['raw_outer_tcp_packets'] - row['raw_outer_udp_packets']
        row['raw_outer_tcp_percent'] = 100 * row['raw_outer_tcp_packets'] / row['raw_packets']
        row['raw_outer_udp_percent'] = 100 * row['raw_outer_udp_packets'] / row['raw_packets']
        rows.append(row)
        if c['protocol_dissector']['raw_packet_protocol_labels'].get('openvpn', 0):
            command = ['tshark', '-n', '-r', str(Path(capture_root) / c['source_pcap']),
                       '-Y', 'openvpn', '-T', 'fields']
            fields = ['frame.number', 'frame.len', 'frame.protocols', 'ip.proto',
                      'udp.length', 'openvpn.opcode', 'openvpn.keyid', '_ws.expert.message']
            for field in fields:
                command += ['-e', field]
            result = subprocess.run(command, text=True, capture_output=True, check=True)
            for line in result.stdout.splitlines():
                values = line.split('\t')
                values += [''] * (len(fields) - len(values))
                record = dict(zip(fields, values))
                record['source_capture'] = c['source_pcap']
                record['inside_icmp_quote'] = ':icmp:ip:udp:openvpn' in record['frame.protocols']
                record['survives_model_filter'] = False if record['inside_icmp_quote'] else None
                observations.append(record)
    return dict(scope='Outer on-wire transport; IPv4 model filter excludes IPv6, ICMP and all UDP. '
                      'TShark protocol-label counts can include protocols nested in ICMP quotations and are not outer L4 counts.',
                captures=rows, openvpn_label_observations=observations,
                confirmed_outer_openvpn_packets=None,
                outer_openvpn_labels=len([r for r in observations if not r['inside_icmp_quote']]),
                openvpn_absence_proven=False)


def group_evidence(captures):
    result = []
    for group in sorted({c['capture_group_id'] for c in captures}):
        members = [c for c in captures if c['capture_group_id'] == group]
        relationships = []
        for a, b in itertools.combinations(members, 2):
            overlap = min(a['last_timestamp'], b['last_timestamp']) - max(a['first_timestamp'], b['first_timestamp'])
            relationships.append(dict(a=a['source_pcap'], b=b['source_pcap'],
                                      overlap_seconds=max(0, overlap), gap_seconds=max(0, -overlap)))
        result.append(dict(capture_group_id=group, members=[c['source_pcap'] for c in members],
                           usable_samples=sum(c['usable_samples'] for c in members), relationships=relationships,
                           evidence=members[0]['group_reason'],
                           independent_of_other_groups='UNVERIFIED',
                           permitted_to_subdivide=False))
    return result


def coverage_status(captures):
    """NULL means not assessed, never zero ciphertext or zero unknown bytes."""
    rows = []
    for scope, ids in [('capture', [c['source_pcap'] for c in captures]), ('class', CLASSES),
                       ('capture_group', sorted({c['capture_group_id'] for c in captures}))]:
        for key in ids:
            selected = [c for c in captures if (c['source_pcap'] if scope == 'capture' else
                        c['labels'][0] if scope == 'class' else c['capture_group_id']) == key]
            counts = collections.Counter()
            for c in selected:
                counts.update(c['stage_counts'])
            rows.append(dict(scope=scope, id=key, captures=len(selected), usable_flows=counts['usable_samples'],
                raw_packets=counts['raw_packets'], model_unique_source_packets=counts['model_unique_source_packets'],
                model_payload_packets=counts['model_payload_packets'], model_payload_bytes=counts['model_real_payload_bytes'],
                packets_with_confirmed_ciphertext=None, packets_without_ciphertext=None,
                packets_with_unsupported_structure=None, framing_bytes=None, plaintext_bytes=None,
                confirmed_ciphertext_bytes=None, authentication_bytes=None, padding_bytes=None, unknown_bytes=None,
                ciphertext_percent=None, unknown_percent=None, unassessed_bytes=counts['model_real_payload_bytes'],
                status='NOT_ASSESSED_AFTER_EVALUATION_STOP'))
    protocol_rows = []
    for protocol in ('tls', 'ssh', 'http', 'ftp', 'stun', 'data'):
        count = sum(c['protocol_dissector']['model_source_packet_protocol_labels'].get(protocol, 0) for c in captures)
        protocol_rows.append(dict(protocol_label=protocol, model_source_packets_with_label=count,
                                  confirmed_ciphertext_bytes=None, coverage_status='NOT_ASSESSED',
                                  caveat='Labels overlap and include handshake/framing packets; not ciphertext coverage.'))
    return dict(status='STOP_NO_CAPTURE_INDEPENDENT_PROTOCOL',
                range_parser_executed=False, randomization_executed=False, representation_rebuilt=False,
                reason='Experiment 1 cannot supply the mandatory capture-independent evaluation protocol. '
                       'Per the phase order, ciphertext range parsing and transformation are not implemented after this STOP.',
                units='Model payload bytes are the first <=150 bytes of first <=50 nonempty TCP payloads per usable flow; padding excluded.',
                null_semantics='Unassessed, not zero. Do not infer that all bytes are ciphertext, plaintext, or unknown.',
                total_captures=len(captures), total_flows=sum(c['usable_samples'] for c in captures),
                total_model_payload_packets=sum(c['stage_counts']['model_payload_packets'] for c in captures),
                total_model_payload_bytes=sum(c['stage_counts']['model_real_payload_bytes'] for c in captures),
                by_scope=rows, protocol_observations=protocol_rows,
                future_protocol_candidates=['TLS 1.2 AES-GCM after complete handshake, negotiated-suite and ChangeCipherSpec validation'],
                insufficient_evidence=['Dissector label or TLS record prefix alone', 'Filename, label or TCP/UDP port',
                                       'CBC encrypted MAC/padding boundaries without keys', 'Unreassembled or midstream TLS/SSH'],
                proposed_ciphertext_seed=32, seed_applied=False, transformation_version=None)


def main():
    inv = read(OUT / 'capture_inventory.json')
    samples = load_samples()
    captures, links = refine_capture_groups(inv['captures'], samples)
    feasibility = assess_feasibility(captures)
    assert feasibility['protocol'] == 'STOP' and not feasibility['training_permitted']
    effective_count = len({c['capture_group_id'] for c in captures})
    final_inv = {**inv, 'captures': captures, 'version': 'capture-audit-v2-conservative-session-links',
                 'conservative_candidate_groups': effective_count,
                 'initial_activity_candidate_groups': inv['conservative_candidate_groups'],
                 'independence_note': 'Effective groups also merge shared endpoint tuples/content hashes. '
                                      'Group count remains an upper bound of unverified acquisition candidates.'}
    save(OUT / 'capture_inventory_effective.json', final_inv)
    csv_save(OUT / 'capture_inventory_effective.csv', [{k: c[k] for k in
        ('source_pcap', 'capture_group_id', 'initial_activity_group_id', 'usable_samples', 'labels',
         'sample_counts', 'first_utc', 'last_utc', 'independently_splittable', 'independence_certified', 'group_reason')}
        for c in captures])
    save(OUT / 'effective_feasibility.json', feasibility)
    group_by_capture = {c['source_pcap']: c['capture_group_id'] for c in captures}
    original_provenance = read(OUT / 'provenance_manifest.json')
    final_provenance = {**original_provenance, 'version': final_inv['version'], 'reason': feasibility['reason'],
        'samples': [{**r, 'capture_group_id': group_by_capture[r['capture']]} for r in original_provenance['samples']]}
    save(OUT / 'provenance_manifest_effective.json', final_provenance)
    save(OUT / 'session_link_evidence.json', dict(links=links, semantics='Conservative union of source groups, '
         'not acquisition-independence certification', initial_groups=18, effective_groups=effective_count))
    totals = collections.Counter()
    for c in captures:
        totals.update(c['stage_counts'])
    before = read(OUT / 'integrity_before.json')
    evidence = group_evidence(captures)
    scope = supplemental_scope(captures, before['capture_root'])
    coverage = coverage_status(captures)
    initial_layer = read(CIPHER_OUT / 'capture_layer_audit.json')
    final_layer = {**initial_layer, 'version': final_inv['version'],
        'grouping_reference': '../capture_disjoint/capture_inventory_effective.json',
        'captures': [{**r, 'capture_group_id': group_by_capture[r['source_capture']],
                     'confidence': dict(retained_layer='HIGH: raw extraction exactly matches cached IPv4/TCP inputs',
                                        application_protocol='Dissector/handshake observations; not ciphertext-range certification',
                                        acquisition_location='UNKNOWN', ciphertext_boundaries='NOT ASSESSED')}
                    for r in initial_layer['captures']]}
    save(CIPHER_OUT / 'capture_layer_audit_effective.json', final_layer)
    layer_csv = []
    outer_by_capture = {r['source_capture']: r for r in scope['captures']}
    for r in final_layer['captures']:
        counts = r['stage_counts']
        outer = outer_by_capture[r['source_capture']]
        row = dict(source_capture=r['source_capture'], class_label=r['class_label'],
                   capture_group_id=r['capture_group_id'], **counts,
                   **{k: v for k, v in outer.items() if k not in ('source_capture', 'class_label', 'raw_packets')},
                   **{k + '_percent_of_raw_packets': 100 * v / counts['raw_packets']
                      for k, v in counts.items() if k.endswith('_packets')},
                   **{k + '_percent_of_raw_captured_bytes': 100 * counts[k] / counts['raw_captured_bytes']
                      for k in ('valid_tcp_ip_bytes', 'eligible_flow_ip_bytes', 'selected_full_payload_bytes',
                                'model_real_header_bytes', 'model_real_payload_bytes')},
                   openvpn_dissector_packets=r['openvpn_dissector_packets'],
                   confirmed_openvpn_packets=None, flows_generated_by_splitcap=None,
                   packets_reaching_actual_npz=None, bytes_reaching_actual_npz=None)
        layer_csv.append(row)
    csv_save(CIPHER_OUT / 'capture_layer_audit_effective.csv', layer_csv)
    save(OUT / 'group_evidence.json', dict(groups=evidence, verified_independence=False,
                                          timestamp_equality_not_proof=True))
    save(CIPHER_OUT / 'transport_scope_audit.json', scope)
    csv_save(CIPHER_OUT / 'transport_scope_audit.csv', scope['captures'])
    save(CIPHER_OUT / 'ciphertext_coverage.json', coverage)
    csv_save(CIPHER_OUT / 'ciphertext_coverage.csv', coverage['by_scope'])
    save(OUT / 'execution.json', dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        starting_commit=before['starting_commit'],
        audit_code_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        commands=["nix-shell recovery/audit-shell.nix --run '.venv-recovery/bin/python -m recovery.capture_audit'",
                  "nix-shell recovery/audit-shell.nix --run '.venv-recovery/bin/python -m recovery.capture_audit_report'"],
        new_training_runs=0, epochs_completed=0, split_seed_requested=32, training_seeds_requested=[32, 42, 52],
        payload_randomization_seed_requested=32, ciphertext_randomization_seed_requested=32,
        seeds_applied_to_new_training=False, transformation_version=None, capture_manifest_version=final_inv['version'],
        software=dict(python=sys.version, **{package: importlib.metadata.version(package)
                       for package in ('numpy', 'torch', 'torch-geometric', 'scikit-learn', 'psutil')}),
        tshark_version=inv['tshark_version'],
        source_sha256={str(p): sha(p) for p in sorted(Path('recovery').glob('*.py'))},
        policy='STOP before six-class training; no test set, checkpoints, metrics or paired comparisons created'))
    summary_rows = []
    for label in CLASSES:
        selected = [c for c in captures if label in c['labels']]
        summary_rows.append([label, len(selected), feasibility['group_counts'][label], sum(c['usable_samples'] for c in selected)])
    counts_table = table(['Class', 'Raw PCAPs', 'Candidate acquisition groups', 'Usable samples'], summary_rows)
    inv_table = table(['Source PCAP', 'Effective candidate group', 'Usable samples', 'UTC acquisition interval'],
        [[c['source_pcap'], c['capture_group_id'], c['usable_samples'],
          c['first_utc'][:19] + ' to ' + c['last_utc'][:19]] for c in captures])
    group_table = table(['Group', 'Members', 'Pair evidence'],
        [[r['capture_group_id'], ', '.join(Path(m).name for m in r['members']),
          ('See session_link_evidence.json and group_evidence.json' if len(r['relationships']) > 3 else
          '; '.join(f"overlap {p['overlap_seconds']:.2f}s / gap {p['gap_seconds']:.2f}s" for p in r['relationships']))
          or 'Only supplied recording; no independent internal subdivision'] for r in evidence])
    text_save('RESULTS_CAPTURE_FEASIBILITY.md', f'''# Capture-independent feasibility: SCIENTIFIC STOP

No six-class training was performed. P2P has a single source recording. Email's two files overlap for approximately 20 minutes and are conservatively one acquisition group. These classes already prevent three-way splitting or two-fold CV, even before additional session links are considered. After conservatively joining shared canonical TCP tuples across activities, Chat and Streaming also each form one effective group. Even disputing those additional links or treating Email A/B as independent would not resolve the single P2P acquisition.

The supplied corpus is `../ICSX-VPN` (local directory spelling), 31 PCAP/PCAPNG files, {totals['raw_packets']:,} packets, 1,902 bidirectional IPv4/TCP tuples and 1,674 eligible samples. Files are full captures containing many flows, not one bidirectional flow per file. No classes or supplied captures were dropped to make evaluation feasible.

## Acquisition grouping and evidence

{counts_table}

There are **{effective_count} effective conservative candidate groups**, not {effective_count} certified independent acquisitions. Genuine independence cannot be counted from the available evidence. Filename pairs were checked against all-packet timestamp bounds. Closely spaced FTPS/SFTP/Vimeo A/B activity recordings and overlapping Chat/Email/Skype-file/VoIP pairs stay together. Hangouts audio 1/2 and Skype audio 1/2 overlap for most of the same call and stay together despite distinct numeric suffixes. This initially gives 18 activity groups. A second check transitively joins activity groups sharing canonical endpoint tuples or exact model representations, following the previous pilot's conservative related-flow policy. Shared TCP tuples across the same-day Chat activities, Streaming activities and April VoIP activities reduce this to {effective_count} effective groups. Tuple reuse is not proof of one acquisition, but does not justify claiming independence. No file-level acquisition logs or reliable interface mapping were supplied. These candidates must not be automatically treated as independent in a future split.

{group_table}

Overlap plus related activity is a conservative reason to group, not proof that every paired byte is duplicated. Non-overlap, different filenames and absence of exact cached-content duplicates do not establish independent acquisition. Possible additional grouping only makes feasibility weaker; the P2P STOP is already unavoidable. All samples from each source retain their acquisition group. No grouping inside a recording is allowed.

## Complete inventory

Each source contains its directory class label; per-class sample counts, hashes, protocol observations, link types and capture metadata are recorded in the JSON/CSV inventory. The final inventory is `capture_inventory_effective.json` / `.csv`; the initial 18-family `capture_inventory.json` / `.csv` is preserved as intermediate evidence, not the final splitting definition. `independently_splittable=false` means a file cannot be divided into independent acquisition sources, not that its whole group could never be allocated once enough independent acquisitions exist.

{inv_table}

## Decision and requirements to resume

`results/capture_disjoint/effective_feasibility.json` records the final STOP; the initial activity-only `feasibility.json` also records STOP. `provenance_manifest_effective.json` maps every original sample to one final source/group without assigning train/validation/test. No split or fold manifest was manufactured. Split seed 32 and training seeds 32/42/52 remain proposed, unapplied settings.

A necessary next step for six-class two-fold evaluation is at least a second demonstrably independent P2P acquisition and independent Email acquisition, plus independent Chat and Streaming acquisitions under the final conservative grouping; all other candidate groups also need provenance verification. Three-way splitting needs at least three verified groups per class and a feasible allocation. Additional filenames or time slices of these recordings do not satisfy that requirement. Fixed epoch-20 evaluation without outer-test checkpoint selection would be appropriate if only two independent groups per class can be established.

The [dataset documentation]({SOURCES['dataset']}) describes regular/VPN captures and OpenVPN UDP, but does not certify the independence or interface of these supplied files. The [official TFE-GNN repository]({SOURCES['upstream']}) describes retaining bidirectional TCP flows. Neither source repairs the missing acquisition diversity.

Reproduce read-only inventory: `nix-shell recovery/audit-shell.nix --run '.venv-recovery/bin/python -m recovery.capture_audit'`. Output writes use exclusive creation and refuse overwriting this audit. Final verification: `python -m recovery.validate_capture_audit` in the same shell.
''')
    with Path('results/multiseed/summary.csv').open() as handle:
        old_rows = list(csv.DictReader(handle))
    old_table = table(['Condition (previous flow-disjoint only)', 'Accuracy mean ± sample SD', 'Macro F1 mean ± sample SD'],
        [[r['condition'], f"{100*float(r['accuracy_mean']):.2f}% ± {100*float(r['accuracy_std']):.2f}%",
          f"{float(r['macro_f1_mean']):.4f} ± {float(r['macro_f1_std']):.4f}"] for r in old_rows])
    text_save('RESULTS_CAPTURE_DISJOINT.md', f'''# Capture-independent TFE-GNN evaluation: STOP before training

Objective: test whether the previous payload advantage survives independent source acquisitions. Status: **no valid six-class capture-independent protocol can be constructed from the supplied captures**. No pilot, full run, checkpoint selection, new predictions, new metrics or paired condition differences were produced. This is a scientific feasibility result, not an accuracy experiment.

## Provenance and protocol

{counts_table}

The 31 recordings form {effective_count} effective conservative acquisition candidates with unverified mutual independence (18 initial activity families, then conservative transitive session links). P2P occurs only in `P2P/vpn_bittorrent.pcap` (233 samples); Email only in the overlapping `Email/vpn_email2a.pcap` and `Email/vpn_email2b.pcap` group (138 samples). Final Chat and Streaming groups also fail the two-group requirement because their activity recordings are linked by reused canonical TCP tuples. A single group cannot occupy both train and test without leakage. Three-way splitting and all-class two-fold CV both fail. Zero capture leakage was not claimed for a nonexistent split. No classes were removed or isolation rules weakened. See [complete feasibility evidence](RESULTS_CAPTURE_FEASIBILITY.md), `results/capture_disjoint/session_link_evidence.json` and `group_evidence.json`.

`provenance_manifest_effective.json` preserves all 1,674 sample IDs, labels, source hashes through the final inventory, canonical tuple/content hashes and effective candidate groups. Automated assertions reject missing/duplicate mappings, changed labels/source identities and group overlap for three-way or per-fold assignments. Grouping and feasibility are invariant to traversal order. No capture split/fold manifest exists; the earlier flow split is preserved exactly and is not relabelled capture-independent. Initial activity inventory and provenance are retained as intermediate audit evidence.

## Preprocessing leakage audit

The adapted runner performs direct source capture → bidirectional IPv4/TCP tuples → `flows.json.gz` → per-packet PyG graphs. It does not execute SplitCap, per-flow PCAP export or NPZ extraction; those actual-stage counts are null. Source identity is retained in `capture`; sample ID hashes the source capture SHA-256 plus canonical tuple hash. Existing `source_family` is a filename heuristic; this audit additionally groups overlapping numbered VoIP pairs. Tuples have no idle timeout and retransmissions remain. Empty-payload flows and flows with more than 10,000 nonempty payload packets are excluded using fixed rules.

Sample-local/deterministic: remove IPv4 addresses/TCP ports; first 50 headers including ACK-only packets; independently first 50 nonempty TCP payloads; 40/150 byte caps; padding token 256; fixed byte vocabulary; PMI/co-occurrence computed within each individual padded packet using window 5 and PMI > 0. There is no corpus-fitted PMI, vocabulary, normalization, threshold or feature selection. PMI weights are calculated for edge selection; the recovered PyG Data stores node bytes and topology, not those computed PMI weights. Existing graph caches therefore do not embed globally estimated corpus statistics. Class counts/content hashes are grouping metadata, not fitted model features.

Learned quantities: neural network weights and BatchNorm running statistics, updated during training only; held-out evaluation uses `model.eval()`. No new fitting occurred. No fold-local correction is needed for currently sample-local graph statistics. A future ciphertext mutation must still happen BEFORE graph construction, rebuilding every byte-dependent feature/topology; unmodified real-payload graphs cannot be reused for transformed bytes. `preprocessing_audit.json` records this audit. No prior graph/cache was changed.

The existing full-payload randomization remains unchanged: SHA-256 of `seed:sample_id:payload_ordinal:payload`, first 16 digest bytes as big-endian seed, NumPy default_rng uniform uint8 [0,255] for original length, then normal truncation/padding/graph construction. Seed 32 is independent of model training seeds. This procedure was not applied in a new experiment.

## Checkpoint and seeds policy

The requested split seed 32, payload seed 32, training seeds 32/42/52 and common 20-epoch budget were retained as planned configuration only. No test data were used for checkpoint/model/hyperparameter selection. With a feasible three-way capture protocol, validation would select checkpoints. With capture CV lacking independent validation captures, the final epoch-20 checkpoint must be used. No unsafe inner-validation substitute was created.

## Previous results and interpretation

{old_table}

These preserved results use three training seeds, one fixed flow-disjoint split and sample standard deviation (ddof=1); they may contain capture leakage. The nine saved prediction sets were independently rechecked during final validation. No new per-run table is presented because zero capture-independent runs were permitted. Absolute performance changes, variance changes and changes in the payload effect across evaluation boundaries cannot be estimated. The old real-vs-random advantage remains a preliminary within-capture result; the present audit cannot establish how much capture-specific information contributed.

## Implementation, validation and resources

The model remains an **adapted PyTorch Geometric reimplementation of original TFE-GNN**. No model or original `src/` file was modified, no official DGL training was executed and no CLE-TFE was used. New project-written code only audits source provenance, raw-to-model extraction, acquisition grouping, stop rules, transport layers and preservation checks. Cross-gated fusion and other adapted/upstream-derived components retain their earlier attribution.

Existing 15 tests passed before changes. The expanded suite, preservation checks, nine old metric recomputations and source SHA-256 comparisons are recorded in `results/capture_disjoint/validation.json` and `tests-after.txt`. No ciphertext transformation tests are claimed: that phase was not reached. Backup branches and original archive are preserved. Exact audit commands and source commit are in `execution.json`.

Read-only capture/TShark audit: sampled process-tree RSS {inv['resources']['peak_process_tree_rss_mib']/1024:.3f} GiB; whole-host RAM {inv['resources']['peak_host_used_mib']/1024:.3f} GiB; sampled device memory {inv['resources']['peak_gpu_device_used_mib']:.1f} MiB. Host memory includes unrelated applications; these are audit peaks, not training peaks. No GPU training, OOM or architecture/batch-size changes occurred. Previous training peaks are unchanged historical measurements.

Limitations: acquisition logs/interface provenance absent; candidate groups may still be related; one P2P/Email acquisition prevents the required design; tuple reuse and fixed truncation are inherited representation limitations; no new CV measurements exist to aggregate. A lower future capture-independent score would be evidence to investigate, not automatically a bug.
''')
    layer_rows = []
    for label in CLASSES:
        members = [c for c in captures if label in c['labels']]
        stage = collections.Counter()
        for c in members:
            stage.update(c['stage_counts'])
        raw = stage['raw_packets']
        outer = [r for r in scope['captures'] if r['class_label'] == label]
        tcp = sum(r['raw_outer_tcp_packets'] for r in outer)
        udp = sum(r['raw_outer_udp_packets'] for r in outer)
        layer_rows.append([label, f'{raw:,}', f'{tcp:,} ({100*tcp/raw:.2f}%)',
                           f'{udp:,} ({100*udp/raw:.2f}%)', f"{stage['eligible_flow_tcp_packets']:,}",
                           f"{stage['model_payload_packets']:,}", f"{stage['model_real_payload_bytes']:,}"])
    layer_table = table(['Class', 'Raw packets', 'Outer TCP', 'Outer UDP', 'Packets in eligible TCP flows',
                         'Nonempty payload packets reaching model', 'Real model payload bytes'], layer_rows)
    retained_table = table(['Source', 'Candidate group', 'Model source packets: TLS / HTTP / SSH', 'Acquisition location'],
        [[c['source_pcap'], c['capture_group_id'],
          ' / '.join(str(c['protocol_dissector']['model_source_packet_protocol_labels'].get(k, 0))
                     for k in ('tls', 'http', 'ssh')), 'UNKNOWN'] for c in captures])
    text_save('RESULTS_CIPHERTEXT_RANDOMIZATION.md', f'''# Ciphertext-only randomization: STOP after capture-layer audit

Experiment 2 cannot use its mandatory evaluation boundary: Experiment 1 has no valid six-class capture-independent split or CV. No ciphertext-only parser, mutation, rebuilt graph cache, pilot, model training or classification result was produced. This report documents the completed read-only layer audit and what remains unassessed. It does not claim ciphertext absence or insufficient byte coverage; the decisive STOP is missing independent evaluation sources.

## Capture point and retained layer

The [ISCXVPN2016 documentation]({SOURCES['dataset']}) describes OpenVPN in UDP mode. Actual supplied captures contain mixed traffic. The adapted TFE-GNN runner retains only valid unfragmented IPv4/TCP packets. It cannot retain the documented outer UDP OpenVPN datagrams. Packet structure exposes ordinary application TLS handshakes, HTTP messages and SSH, rather than uniformly VPN tunnel ciphertext. This is application TCP traffic; whether observed before VPN encryption, after VPN decryption or on a particular interface remains UNKNOWN. Raw-IP link type alone does not resolve that location. Some unknown TCP payloads remain uninterpreted; they are not declared encrypted solely by label or filename.

There are 29 raw-IP captures and two Ethernet VoIP captures. `vpn_hangouts_audio2.pcap` is actually PCAPNG; its metadata identifies Editcap 1.12.3, with no supplied interface name/location. The two Ethernet captures also contain 1,540 excluded IPv6 frames. Original stage JSON counts `raw_tcp_packets`/`raw_udp_packets` refer to outer IPv4. `transport_scope_audit.json` adds outer IPv6 transport counts and unambiguous all-network totals; protocol dissector counters can include nested ICMP quotations and should not replace outer L4 counts.

TShark labelled six packets as OpenVPN, all in `vpn_voipbuster1b.pcap`, frames 177433–177438. Their actual stack is `eth:ethertype:ip:icmp:ip:udp:openvpn`: quoted datagrams in ICMP errors, not retained TCP packets. No direct outer OpenVPN dissection label occurred. This does not prove OpenVPN is absent on arbitrary ports, or certify unknown UDP data. Confirmed outer OpenVPN counts remain null. All six quoted matches are excluded from model inputs; model OpenVPN labels are zero.

## Quantitative stage trace

{layer_table}

Across all files: {totals['raw_packets']:,} raw packets; {sum(r['raw_outer_tcp_packets'] for r in scope['captures']):,} outer TCP; {sum(r['raw_outer_udp_packets'] for r in scope['captures']):,} outer UDP. All {totals['valid_tcp_packets']:,} valid IPv4/TCP packets survive the network/transport filter, before flow exclusions. There are {totals['all_bidirectional_tcp_tuples']:,} logical bidirectional TCP tuples, {totals['usable_samples']:,} eligible flows, and {totals['eligible_flow_tcp_packets']:,} packets in those flows. The exact model uses {totals['model_header_packets']:,} header packets and {totals['model_payload_packets']:,} nonempty payload packets, whose union is {totals['model_unique_source_packets']:,} source packets; header/payload selection is independent, so do not add these counts.

Selected full payloads contain {totals['selected_full_payload_bytes']:,} bytes. The 150-byte cap leaves {totals['model_real_payload_bytes']:,} real payload bytes; sanitized/truncated headers contain {totals['model_real_header_bytes']:,} bytes. Padding expands payload input to {totals['model_payload_tokens_with_padding']:,} tokens and header input to {totals['model_header_tokens_with_padding']:,} tokens; token 256 is not a captured byte. Full stage packet counts and percentages plus byte counts/percentages for every capture are in `capture_layer_audit_effective.json` / `.csv`; all-network outer-L4 percentages are in `transport_scope_audit.csv`. Per-class stage percentages are in `stage_summary.csv`. The original `capture_layer_audit.json` / `.csv` is retained as intermediate evidence using the initial 18 activity groups; final effective group IDs are in the `_effective` files, consistent with the final provenance inventory and coverage denominators.

Actual path: raw PCAP/PCAPNG → in-memory canonical bidirectional TCP tuple grouping → `data/recovery/flows.json.gz` → capped/padded header and payload sequences → packet-local PMI byte graphs → PyG model. There is no executed SplitCap, per-flow PCAP or NPZ stage in this adapted runner; generated SplitCap flow counts and actual NPZ packet/byte counts are null, not fabricated. Source-packet indices and exact cached byte sequences were re-extracted and checked across every usable flow. No original payload bytes were printed or saved in new audit outputs.

## Protocol observations per capture

{retained_table}

Counts above are overlapping TShark labels on the 69,321 model-source packets, not encrypted-payload counts. TLS-labelled packets include plaintext handshakes, framing and protected records. SSH observations are concentrated in supplied SFTP captures, but filenames did not determine protocol assignment. Raw UDP additionally has DNS, STUN, RTCP, legacy QUIC and DHT dissections; none survives IPv4/TCP filtering. Occasional heuristic labels, including apparent WireGuard in 2015 traffic, are not accepted as protocol proof. Every capture's raw L4 counts, metadata, server-hello fields and retained labels are saved with evidence/confidence caveats.

## Defensible boundaries and coverage status

An observed Email server hello (`vpn_email2b.pcap`, frame 204) negotiates TLS 1.2 (`0x0303`), cipher suite `0xc02f`, compression 0; other observed suites include `0x002f`. For TLS 1.2 AES-GCM, a future parser can use complete reassembled records and verified negotiation/ChangeCipherSpec state to separate the record header, explicit nonce, protected body and authentication tag. [RFC 5288]({SOURCES['gcm']}) specifies the 8-byte explicit nonce and 16-byte tag; [RFC 5289]({SOURCES['ecdhe_gcm']}) identifies the ECDHE AES-GCM suite. These fields establish a candidate protocol, not byte-range coverage of the actual truncated model inputs.

TLS CBC padding and encrypted MAC boundaries cannot simply be guessed without keys. SSH encrypts packet-length/padding fields after key exchange, so a prefix or port does not locate safe body-only ranges. [TLS 1.2]({SOURCES['tls12']}) and [SSH transport]({SOURCES['ssh']}) specifications must guide any later parser. Missing handshakes, gaps, truncation, retransmissions and renegotiation require conservative rejection/unknown handling. Unknown UDP regions must not be called OpenVPN ciphertext; the model does not consume UDP in any event.

| Coverage quantity | Current status |
| --- | --- |
| Source captures / usable flows | 31 / 1,674 |
| Model-source packets / nonempty payload packets | 69,321 / 40,962 |
| Actual retained payload bytes | 4,666,377 |
| Confirmed ciphertext packets/bytes, framing, plaintext, tags, padding, unknown bytes | NOT ASSESSED (null) |
| Ciphertext / unknown percentages | NOT ASSESSED (null) |
| Byte ranges transformed / graphs rebuilt | None; transformation phase not reached |

`ciphertext_coverage.json` and `.csv` preserve exact payload denominators by capture, class and candidate acquisition group; category totals are null, with all bytes explicitly marked unassessed. Null is not zero ciphertext or 100% unknown protocol. Protocol-label observations are provided separately and do not substitute for byte coverage. There is no transformation audit pretending validation succeeded; no randomization algorithm/version was instantiated. Proposed ciphertext seed 32 was not applied. No test of packet-specific ciphertext mutation/determinism or graph reconstruction is claimed.

## Interpretation and limitations

No Real-vs-Ciphertext-randomized metrics, paired differences or new scientific ciphertext conclusions exist. The previously observed payload effect could reflect plaintext, framing, application-protocol structure, encrypted regions, session/capture artifacts or optimization behavior. It cannot be attributed to VPN ciphertext. Additional demonstrably independent acquisitions are required first; only then should region identification/coverage, packet-specific SHA-256 randomization, non-ciphertext preservation and complete byte-derived graph reconstruction be implemented and validated before training. Original captures and earlier reports/results/caches remain unchanged; final checks are in `results/capture_disjoint/validation.json`.
''')
    summary = []
    for label in [*CLASSES, 'ALL']:
        selected = [c for c in captures if label == 'ALL' or label in c['labels']]
        counts = collections.Counter()
        for c in selected:
            counts.update(c['stage_counts'])
        raw, raw_bytes = counts['raw_packets'], counts['raw_captured_bytes']
        summary.append(dict(class_label=label, **counts,
            **{k + '_percent_of_raw_packets': 100 * counts[k] / raw for k in
               ('raw_tcp_packets', 'raw_udp_packets', 'valid_tcp_packets', 'eligible_flow_tcp_packets',
                'model_header_packets', 'model_payload_packets', 'model_unique_source_packets')},
            **{k + '_percent_of_raw_captured_bytes': 100 * counts[k] / raw_bytes for k in
               ('valid_tcp_ip_bytes', 'eligible_flow_ip_bytes', 'selected_full_payload_bytes',
                'model_real_header_bytes', 'model_real_payload_bytes')}))
    csv_save(CIPHER_OUT / 'stage_summary.csv', summary)
    print('Published three STOP reports, acquisition evidence and unassessed-coverage denominators.', flush=True)


if __name__ == '__main__':
    main()
