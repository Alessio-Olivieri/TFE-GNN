# Capture-independent feasibility: SCIENTIFIC STOP

No six-class training was performed. P2P has a single source recording. Email's two files overlap for approximately 20 minutes and are conservatively one acquisition group. These classes already prevent three-way splitting or two-fold CV, even before additional session links are considered. After conservatively joining shared canonical TCP tuples across activities, Chat and Streaming also each form one effective group. Even disputing those additional links or treating Email A/B as independent would not resolve the single P2P acquisition.

The supplied corpus is `../ICSX-VPN` (local directory spelling), 31 PCAP/PCAPNG files, 4,835,981 packets, 1,902 bidirectional IPv4/TCP tuples and 1,674 eligible samples. Files are full captures containing many flows, not one bidirectional flow per file. No classes or supplied captures were dropped to make evaluation feasible.

## Acquisition grouping and evidence

| Class | Raw PCAPs | Candidate acquisition groups | Usable samples |
| --- | --- | --- | --- |
| Chat | 10 | 1 | 183 |
| Email | 2 | 1 | 138 |
| FileTransfer | 6 | 3 | 290 |
| P2P | 1 | 1 | 233 |
| Streaming | 5 | 1 | 276 |
| VoIP | 7 | 2 | 554 |

There are **9 effective conservative candidate groups**, not 9 certified independent acquisitions. Genuine independence cannot be counted from the available evidence. Filename pairs were checked against all-packet timestamp bounds. Closely spaced FTPS/SFTP/Vimeo A/B activity recordings and overlapping Chat/Email/Skype-file/VoIP pairs stay together. Hangouts audio 1/2 and Skype audio 1/2 overlap for most of the same call and stay together despite distinct numeric suffixes. This initially gives 18 activity groups. A second check transitively joins activity groups sharing canonical endpoint tuples or exact model representations, following the previous pilot's conservative related-flow policy. Shared TCP tuples across the same-day Chat activities, Streaming activities and April VoIP activities reduce this to 9 effective groups. Tuple reuse is not proof of one acquisition, but does not justify claiming independence. No file-level acquisition logs or reliable interface mapping were supplied. These candidates must not be automatically treated as independent in a future split.

| Group | Members | Pair evidence |
| --- | --- | --- |
| Chat/linked-c257653d273a | vpn_aim_chat1a.pcap, vpn_aim_chat1b.pcap, vpn_facebook_chat1a.pcap, vpn_facebook_chat1b.pcap, vpn_hangouts_chat1a.pcap, vpn_hangouts_chat1b.pcap, vpn_icq_chat1a.pcap, vpn_icq_chat1b.pcap, vpn_skype_chat1a.pcap, vpn_skype_chat1b.pcap | See session_link_evidence.json and group_evidence.json |
| Email/vpn_email2 | vpn_email2a.pcap, vpn_email2b.pcap | overlap 1217.21s / gap 0.00s |
| FileTransfer/vpn_ftps | vpn_ftps_A.pcap, vpn_ftps_B.pcap | overlap 0.00s / gap 9.25s |
| FileTransfer/vpn_sftp | vpn_sftp_A.pcap, vpn_sftp_B.pcap | overlap 0.00s / gap 13.68s |
| FileTransfer/vpn_skype_files1 | vpn_skype_files1a.pcap, vpn_skype_files1b.pcap | overlap 3582.99s / gap 0.00s |
| P2P/vpn_bittorrent | vpn_bittorrent.pcap | Only supplied recording; no independent internal subdivision |
| Streaming/linked-344af536ded1 | vpn_netflix_A.pcap, vpn_spotify_A.pcap, vpn_vimeo_A.pcap, vpn_vimeo_B.pcap, vpn_youtube_A.pcap | See session_link_evidence.json and group_evidence.json |
| VoIP/linked-99e47ec66892 | vpn_facebook_audio2.pcap, vpn_hangouts_audio1.pcap, vpn_hangouts_audio2.pcap, vpn_skype_audio1.pcap, vpn_skype_audio2.pcap | See session_link_evidence.json and group_evidence.json |
| VoIP/vpn_voipbuster1 | vpn_voipbuster1a.pcap, vpn_voipbuster1b.pcap | overlap 3597.69s / gap 0.00s |

Overlap plus related activity is a conservative reason to group, not proof that every paired byte is duplicated. Non-overlap, different filenames and absence of exact cached-content duplicates do not establish independent acquisition. Possible additional grouping only makes feasibility weaker; the P2P STOP is already unavoidable. All samples from each source retain their acquisition group. No grouping inside a recording is allowed.

## Complete inventory

Each source contains its directory class label; per-class sample counts, hashes, protocol observations, link types and capture metadata are recorded in the JSON/CSV inventory. The final inventory is `capture_inventory_effective.json` / `.csv`; the initial 18-family `capture_inventory.json` / `.csv` is preserved as intermediate evidence, not the final splitting definition. `independently_splittable=false` means a file cannot be divided into independent acquisition sources, not that its whole group could never be allocated once enough independent acquisitions exist.

| Source PCAP | Effective candidate group | Usable samples | UTC acquisition interval |
| --- | --- | --- | --- |
| Chat/vpn_aim_chat1a.pcap | Chat/linked-c257653d273a | 5 | 2015-06-03T18:40:21 to 2015-06-03T18:57:31 |
| Chat/vpn_aim_chat1b.pcap | Chat/linked-c257653d273a | 4 | 2015-06-03T18:40:21 to 2015-06-03T18:57:26 |
| Chat/vpn_facebook_chat1a.pcap | Chat/linked-c257653d273a | 51 | 2015-06-03T17:57:03 to 2015-06-03T18:15:04 |
| Chat/vpn_facebook_chat1b.pcap | Chat/linked-c257653d273a | 6 | 2015-06-03T17:57:03 to 2015-06-03T18:14:30 |
| Chat/vpn_hangouts_chat1a.pcap | Chat/linked-c257653d273a | 58 | 2015-06-03T19:52:00 to 2015-06-03T20:07:40 |
| Chat/vpn_hangouts_chat1b.pcap | Chat/linked-c257653d273a | 34 | 2015-06-03T19:51:58 to 2015-06-03T20:07:36 |
| Chat/vpn_icq_chat1a.pcap | Chat/linked-c257653d273a | 5 | 2015-06-03T19:00:55 to 2015-06-03T19:23:10 |
| Chat/vpn_icq_chat1b.pcap | Chat/linked-c257653d273a | 1 | 2015-06-03T19:00:54 to 2015-06-03T19:23:11 |
| Chat/vpn_skype_chat1a.pcap | Chat/linked-c257653d273a | 10 | 2015-06-03T17:31:23 to 2015-06-03T17:47:50 |
| Chat/vpn_skype_chat1b.pcap | Chat/linked-c257653d273a | 9 | 2015-06-03T17:31:20 to 2015-06-03T17:47:42 |
| Email/vpn_email2a.pcap | Email/vpn_email2 | 65 | 2015-06-08T14:24:01 to 2015-06-08T14:45:14 |
| Email/vpn_email2b.pcap | Email/vpn_email2 | 73 | 2015-06-08T14:24:57 to 2015-06-08T14:45:14 |
| FileTransfer/vpn_ftps_A.pcap | FileTransfer/vpn_ftps | 60 | 2015-05-22T19:40:21 to 2015-05-22T19:46:24 |
| FileTransfer/vpn_ftps_B.pcap | FileTransfer/vpn_ftps | 40 | 2015-05-22T19:46:33 to 2015-05-22T19:49:49 |
| FileTransfer/vpn_sftp_A.pcap | FileTransfer/vpn_sftp | 6 | 2015-05-22T19:21:27 to 2015-05-22T19:26:57 |
| FileTransfer/vpn_sftp_B.pcap | FileTransfer/vpn_sftp | 5 | 2015-05-22T19:27:10 to 2015-05-22T19:31:03 |
| FileTransfer/vpn_skype_files1a.pcap | FileTransfer/vpn_skype_files1 | 82 | 2015-06-05T13:50:21 to 2015-06-05T14:50:04 |
| FileTransfer/vpn_skype_files1b.pcap | FileTransfer/vpn_skype_files1 | 97 | 2015-06-05T13:50:19 to 2015-06-05T14:53:45 |
| P2P/vpn_bittorrent.pcap | P2P/vpn_bittorrent | 233 | 2015-06-04T12:33:09 to 2015-06-04T12:36:52 |
| Streaming/vpn_netflix_A.pcap | Streaming/linked-344af536ded1 | 60 | 2015-05-24T17:03:24 to 2015-05-24T17:32:56 |
| Streaming/vpn_spotify_A.pcap | Streaming/linked-344af536ded1 | 41 | 2015-05-24T15:41:16 to 2015-05-24T16:45:55 |
| Streaming/vpn_vimeo_A.pcap | Streaming/linked-344af536ded1 | 37 | 2015-05-24T17:48:27 to 2015-05-24T18:10:43 |
| Streaming/vpn_vimeo_B.pcap | Streaming/linked-344af536ded1 | 37 | 2015-05-24T18:14:58 to 2015-05-24T18:30:44 |
| Streaming/vpn_youtube_A.pcap | Streaming/linked-344af536ded1 | 101 | 2015-05-24T18:32:17 to 2015-05-24T19:17:03 |
| VoIP/vpn_facebook_audio2.pcap | VoIP/linked-99e47ec66892 | 138 | 2015-04-14T19:03:03 to 2015-04-14T20:12:13 |
| VoIP/vpn_hangouts_audio1.pcap | VoIP/linked-99e47ec66892 | 126 | 2015-04-14T20:14:36 to 2015-04-14T21:12:04 |
| VoIP/vpn_hangouts_audio2.pcap | VoIP/linked-99e47ec66892 | 132 | 2015-04-14T20:12:29 to 2015-04-14T21:29:45 |
| VoIP/vpn_skype_audio1.pcap | VoIP/linked-99e47ec66892 | 79 | 2015-04-14T17:55:42 to 2015-04-14T19:00:10 |
| VoIP/vpn_skype_audio2.pcap | VoIP/linked-99e47ec66892 | 44 | 2015-04-14T17:55:00 to 2015-04-14T19:00:38 |
| VoIP/vpn_voipbuster1a.pcap | VoIP/vpn_voipbuster1 | 19 | 2015-05-22T16:33:20 to 2015-05-22T17:33:20 |
| VoIP/vpn_voipbuster1b.pcap | VoIP/vpn_voipbuster1 | 16 | 2015-05-22T16:33:22 to 2015-05-22T17:33:31 |

## Decision and requirements to resume

`results/capture_disjoint/effective_feasibility.json` records the final STOP; the initial activity-only `feasibility.json` also records STOP. `provenance_manifest_effective.json` maps every original sample to one final source/group without assigning train/validation/test. No split or fold manifest was manufactured. Split seed 32 and training seeds 32/42/52 remain proposed, unapplied settings.

A necessary next step for six-class two-fold evaluation is at least a second demonstrably independent P2P acquisition and independent Email acquisition, plus independent Chat and Streaming acquisitions under the final conservative grouping; all other candidate groups also need provenance verification. Three-way splitting needs at least three verified groups per class and a feasible allocation. Additional filenames or time slices of these recordings do not satisfy that requirement. Fixed epoch-20 evaluation without outer-test checkpoint selection would be appropriate if only two independent groups per class can be established.

The [dataset documentation](https://www.unb.ca/cic/datasets/vpn.html) describes regular/VPN captures and OpenVPN UDP, but does not certify the independence or interface of these supplied files. The [official TFE-GNN repository](https://github.com/ViktorAxelsen/TFE-GNN) describes retaining bidirectional TCP flows. Neither source repairs the missing acquisition diversity.

Reproduce read-only inventory: `nix-shell recovery/audit-shell.nix --run '.venv-recovery/bin/python -m recovery.capture_audit'`. Output writes use exclusive creation and refuse overwriting this audit. Final verification: `python -m recovery.validate_capture_audit` in the same shell.
