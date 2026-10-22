# SELinux evidence record

Status: reviewed

The SELinux detector asks whether SELinux is enforcing for this app, whether the loaded policy grants rules stock policy denies, and whether audit output looks rewritten. An enforcing, clean result means these checks saw nothing wrong, not that the policy is stock.

## Signals

### Enforcement status

- Observable signal: /sys/fs/selinux/enforce, getenforce, the selinuxfs mount and this process's context in /proc/self/attr/current.
- Producing subsystem: the kernel's SELinux LSM and selinuxfs.
- Mechanism: selinuxfs exposes the enforce node to all readers; a denied read while the domain is enforcing, or a labelled context, bound what the mode can be.
- References: kernel/common security/selinux/selinuxfs.c (enforce node mode) and security/selinux/avc.c (avc_denied only denies when enforcing); system/sepolicy private/domain.te (every domain may search selinuxfs and getattr its files); Android CDD 9.7 (global enforcing mode is required).
- Applicability: every supported release.
- Visibility limits: some devices deny reading enforce; a denied read proves enforcing only through the paradox rule, and a labelled context proves SELinux is enabled, not enforcing.
- Result states: enforcing, enforcing (paradox), permissive, disabled, not observable, unknown.
- Interpretation: permissive or disabled are compatibility departures reported as danger; an unresolved mode stays unknown rather than defaulting to enforcing.

### Dirty policy rules

- Observable signal: whether the loaded policy allows edges stock policy denies, such as untrusted_app to magisk binder call or system_server execmem.
- Producing subsystem: the loaded SELinux policy, queried through an app_zygote access oracle.
- Mechanism: the capability asks security_compute_av style questions from app_zygote, with a control edge stock policy allows and one it denies to prove the oracle answers.
- References: system/sepolicy private/app_neverallows.te and the domain .te files for the stock expectations; capability/selinuxpolicy/EVIDENCE.md for the oracle.
- Applicability: Android releases whose app_zygote can reach the oracle; see the capability record.
- Visibility limits: an oracle that fails its own controls is untrusted; its answers are shown at lower confidence.
- Result states: rule present, not observed, untrusted oracle, unavailable.
- Interpretation: a trusted oracle's allowed edge is danger or a policy observation, as each rule's text says; untrusted answers never exceed warning.

### Context validity

- Observable signal: whether root-tool contexts are valid in the loaded policy, and the native and Java app_zygote tracks that carry the checks.
- Producing subsystem: the loaded SELinux policy, queried by the selinuxpolicy capability's carriers.
- Mechanism: a context is valid only if the loaded policy defines it, so a root-tool domain's validity shows the policy was extended.
- References: kernel/common security/selinux/selinuxfs.c (sel_write_context); capability/selinuxpolicy/EVIDENCE.md.
- Applicability: where a carrier can start.
- Visibility limits: a carrier that cannot start leaves the check unavailable.
- Result states: clean, valid root context, unavailable.
- Interpretation: a valid root-tool context is supporting evidence of a modified policy.

### Policy reload and status page

- Observable signal: the app_zygote seqno oracle: the status page's policyload counter against the access oracle's sequence number, and whether reading the status page killed the disposable child that read it.
- Producing subsystem: selinuxfs's status and access nodes, read through the selinuxpolicy capability's app_zygote carrier.
- Mechanism: a policy reload after boot, as root tools do to inject rules, leaves the two counters apart; a hook on the status node's open handler breaks its mapping, and the read kills the reader.
- References: kernel/common security/selinux/selinuxfs.c (status and access nodes); capability/selinuxpolicy/EVIDENCE.md (Policy reload and process context, Status page mapping).
- Applicability: where the app_zygote carrier starts; the oracle needs android:zygotePreloadName.
- Visibility limits: an odd sequence was read mid-update; a status page that was not read leaves the oracle unavailable.
- Result states: clean, seqno split, status page faulted, info, unavailable.
- Interpretation: a seqno split and a faulted status page are danger: the first shows a policy reload after boot, the second a status node whose kernel handler was altered. Info and unavailable leave the verdict to the other checks.

### Audit integrity

- Observable signal: whether a controlled AVC denial appears in app-readable auditd logs, whether allow or rewrite markers appear, and auditpatch module residue.
- Producing subsystem: logd's audit buffer and libselinux's callback in this process.
- Mechanism: a module that rewrites logd's audit output leaves the controlled denial missing, altered or tagged.
- References: system/sepolicy private/file_contexts (/data/adb is adb_data_file, not searchable by apps). Discovery only for the ZN-AuditPatch residue paths and log markers.
- Applicability: devices where the app can read its own audit events.
- Visibility limits: AOSP does not guarantee that apps see matching audit events; residue under /data/adb is not observable from apps.
- Result states: clear, residue, exposed, tampered, inconclusive; residue rows can be not observable.
- Interpretation: tampering is warning or danger; absence of residue or events is inconclusive.

### Policy analysis

- Observable signal: the policy version, dangerous types and permissive domains visible through selinuxfs.
- Producing subsystem: the loaded policy's exported metadata.
- Mechanism: a policy version below the release's minimum, root-tool types or permissive domains indicate a modified or debug policy.
- References: kernel/common security/selinux/selinuxfs.c for the exported nodes. Discovery only for the list of root-tool types.
- Applicability: readable only where selinuxfs grants the app those nodes.
- Visibility limits: unreadable nodes leave the analysis partial.
- Result states: strong, minor drift, review, weak, unreadable.
- Interpretation: permissive domains and dangerous types are warning or danger; unreadable fields are support.

### SID-table query consistency

- Observable signal: the selinuxpolicy capability's paired context-query/attr-current SID-table counter observations, repeated twice with four distinct canonical stock contexts per round.
- Producing subsystem: SELinux context registration in the current policy, compared across selinuxfs/context and the process attribute handler; see the capability's SID-table registration experiment.
- Mechanism: a query that only inserts into a backup SID table can accept a context without increasing live entries; a later attr/current write passed to the original handler can insert that same context into the live table even when its transition is denied. Both rounds must show context delta 0, attr delta 4, repeat delta 0, unchanged control/idle counts, an accepted carrier label, malformed context and attr/current controls rejected with EINVAL, successful canonical queries, issued attr writes rejected with EACCES, unchanged child identity and eight distinct candidates. The attr/current control is what places those EACCES rejections after context conversion; EPERM is not accepted because `proc_pid_attr_write` can return it before the SELinux hook runs. The alternate complete pattern (context delta 4, attr delta 0, repeat delta 0) is only "no discrepancy observed". Every other pattern is inconclusive.
- References: ACK [selinuxfs.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/selinuxfs.c) (`sel_write_context`) and [hooks.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/hooks.c) (`selinux_setprocattr`); the other pinned ACK/AOSP references in capability/selinuxpolicy/EVIDENCE.md; [KernelSU a810677b847ba564c5f9d3fa0fbabe54794b8eef](https://github.com/tiann/KernelSU/commit/a810677b847ba564c5f9d3fa0fbabe54794b8eef) and its parent `24d9bc3`, `kernel/feature/selinux_hide.c` (`my_write_context`, `my_write_access`, `my_setprocattr`). The parent routes app UID queries to a backup policy without global registration; the fix adds global conversions. This implementation measures context/attr paths, not the access path.
- Applicability: gated by the capability's carrier, interface and canonical context checks. The counter pattern is intended to expose unsynchronized query/registration implementations; KernelSU with hiding disabled or with this synchronization fix can behave like stock. KernelSU's SELinux hiding is opt-in: `ksu_selinux_hide_enabled` defaults to false, and enabling it fails with "please save feature and reboot" until a backup policy was captured at boot, which is dropped again when hiding stays off. The unsynchronized hooks (`my_write_context` answering app UIDs from the backup policy, `my_setprocattr` passing stock-valid labels to the original handler) ship in releases [v3.2.5](https://github.com/tiann/KernelSU/blob/b0bc817b4e966aa6aa830834eaf6ef765d821d40/kernel/feature/selinux_hide.c) and [v3.3.0](https://github.com/tiann/KernelSU/blob/932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e/kernel/feature/selinux_hide.c); neither contains a810677. Among forks, KernelSU-Next carries the synchronization in [e01796b9](https://github.com/KernelSU-Next/KernelSU-Next/commit/e01796b94097e6bef8dffadcaacd78cfff1c18c6), while SukiSU-Ultra's file was last changed in [cf785ef9](https://github.com/SukiSU-Ultra/SukiSU-Ultra/blob/cf785ef9d681ac400848599c2f59e49f677bfd07/kernel/feature/selinux_hide.c) without it. These are source observations at the cited revisions; KernelSU forks/releases are not classified by version strings.
- Visibility limits: total entries are global, random candidates are not proven fresh, and a hidden reload or other processes can imitate/mask a paired pattern. Controls reduce ambiguity but cannot make these observations independent or authoritative. Control failures, missing/older payloads, permissions and incomplete measurements are not negative results.
- Result states: repeated discrepancy observed, no discrepancy observed, not collected, unsupported, permission limited, unavailable, inconclusive.
- Interpretation: repeated discrepancy is warning-level supporting evidence only, never KernelSU identification, root proof or a danger verdict. It ranks below the danger findings, a trusted dirty-policy rule hit and an untrusted carrier, and above the reduced-coverage carrier state, so that info-level state cannot hide it. Only a discrepancy adds a summary sentence and an impact item; no discrepancy observed and all failure/coverage states stay in informational method rows. This shares SELinux mechanisms with the context/access/seqno observations and is not counted as another independent root indicator.

Initial validation is source review plus JVM and injected native regression tests. Real
stock/pre-fix/fixed-kernel device measurements have not been obtained. The row and export
state the global-statistics limitation and the retained preload capture time; no sensitivity,
false-positive rate or coverage of all Android kernels is claimed.

### Experimental App Zygote AVC lookup profile

- Observable signal: the selinuxpolicy capability's per-batch AVC lookup deltas for payloads A and B (four rounds of 4096 rejected attr/current writes each, on one pinned CPU), its collection state and the paired timing medians.
- Producing subsystem: the SELinux attr/current handler and the AVC's per-CPU statistics, measured in a disposable child of the app_zygote preload; see the capability's App Zygote AVC lookup counters record.
- Mechanism: only a collected snapshot is classified. A payload costs one lookup per write when every batch lies in [1, 1.1] x 4096 lookups and two when every batch lies in [2, 2.1] x 4096; anything else, including rounds that disagree, is unclassified. Extra activity on the CPU and the counter reads only add lookups, so the bands allow a tenth above each count and nothing below it. A≈1/B≈1 is the stock handler's count; A≈1/B≈2 and A≈2/B≈2 mean an extra AVC query on the write path. Timing is shown but never classified, because the stock handler already treats the payloads differently.
- References: capability/selinuxpolicy/EVIDENCE.md (App Zygote AVC lookup counters) for the pinned ACK, AOSP and KernelSU sources and the source-derived lookup table; ACK [hooks.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/hooks.c) (`selinux_setprocattr`) and [avc.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/avc.c) (`avc_lookup`).
- Applicability: wherever the capability collected counters; see its record. The AVC carrier gate permits app_zygote MLS category suffixes, while full-label identity changes still invalidate collection. The KernelSU shapes in its table come from source review at the cited revisions, not from device measurements, and forks or later revisions can differ.
- Visibility limits: the counter is shared by every task on the CPU and does not show which code made a query, so a profile cannot attribute the extra lookup to KernelSU or to any tool. A≈1/B≈1 cannot exclude hooks that query only after their own parse fails, which includes KernelSU from df03912 with hiding enabled. Missing counters, permission limits and failed collection are coverage gaps, not negative results.
- Result states: A≈1/B≈1, A≈1/B≈2, A≈2/B≈2, unclassified (typed as `SelinuxAvcLookupProfile`); not collected, timing only, permission limited, unsupported, unavailable, inconclusive (`SelinuxAvcLookupCollection`).
- Interpretation: informational only. A≈1/B≈2 and A≈2/B≈2 add one informational impact line; every reading stays an informational method row and never changes the card's status, verdict or summary, and A≈1/B≈1 is shown as not clean. This shares the attr/current path with the controlled context-write and timing observations and is not counted as an independent root indicator.

### App Zygote invalid-context timing (experimental)

Current contract: a lightweight disposable child verifies the B/A EINVAL controls
before the unpinned preload parent collects 32 warmup and 512 AB/BA pairs. The full
pinned AVC child runs afterward. The parent accepts only pairs whose sampled CPU
endpoints both equal its entry CPU; this also rejects a move between pairs without
changing affinity. Endpoint checks cannot detect an unobserved move away and back.
A completed parent sample is retained even if the later optional AVC child fails.
Its own errors, identity checks, medians and completion state determine usability.

Timing direction is informational only. A positive direction requires a positive
paired lower median, at least 12/16 positive blocks and more than 256 A-slower
pairs. A negative direction requires a negative paired lower median, at least
12/16 negative blocks and at most 256 A-slower pairs. Other complete samples are
inconclusive; missing and legacy parent samples are unavailable. These consistency
gates are diagnostic conventions, not calibrated statistical significance tests.
Neither direction changes the card's integrity status or sets `isSecure`.
Stock GKI already parses A but skips B before credential allocation, so it supplies
no guaranteed timing sign. The CPU crossover measurements below reinforce that
limitation. No matched stock/OEM/kernel calibration is available to justify a
universal positive-sign hiding verdict. Historical Danger policies described below
refer to earlier experimental builds, not the current interpretation.

The preflight limits obvious fault/permission failures to a disposable child; it
does not prove that an arbitrary modified handler will behave identically in the
live parent. Parent writes are synchronous and have no interruptible syscall
deadline. The host acquisition and bootstrap tests target the standard unminified debug APK.
A minified release instrumentation target needs its own reviewed test/keep-rule
setup; copying duplicate runtime JARs into every test classpath is not used.
No new physical-device measurements accompany the current consistency
and evidence-retention changes; host/JVM tests validate their control flow only.

#### CPU crossover counterexample (2026-10-20)

The user reported reducing the kernel's Hide latency. The exact kernel patch was
not available for review. On the connected physical device, `ksud feature list`
reported `selinux_hide` enabled; it was not toggled during this experiment.
All runs kept `com.eltavine.duckdetector` and UID 10625. No uninstall, data clear,
reboot, or package rename was used. Each round below created distinct preload
parent/child PIDs and ran two scans of its retained result. Every strict acquisition
test passed: 512 pairs in each process, zero child migrations, available medians,
complete parent timing, and a returned carrier snapshot. Positive classification
was deliberately not required by these acquisition tests.

| Configuration (three fresh preloads each) | Child paired medians A−B (ns) | Parent paired medians A−B (ns) |
| --- | --- | --- |
| Original trace Debug, CPU 0, initial screen-off group | -416, 260, 989 | 260, 209, 208 |
| Original trace Debug, CPU 0, wake before each round | 261, -51, 469 | 260, 209, 209 |
| Timing sources O2, CPU 0, wake before each round | 260, 157, 208 | 261, 261, 156 |
| Timing sources O2, CPU 7, wake before each round | -52, -52, -103 | -53, -52, -104 |
| Same O2 CPU 0 APK reinstalled, wake before each round | 521, 416, 364 | 260, 155, 260 |
| Additional O2 CPU 0 runs before restoring the trace APK | 312, 260, 521 | -52, 261, 208 |

The device was observed in Dozing state after the initial group; subsequent groups
explicitly sent WAKEUP before each round. Frequency, temperature, and background
load were not fixed. The screen-off and awake groups must not be pooled as a
controlled power-state experiment.

The controlled O2 builds differ only in CPU selection: ascending allowed-CPU search
selected CPU 0, while descending search selected CPU 7. Both timing implementation
files were compiled with verified `-O2`; the sampling and classification code was
otherwise unchanged between these two builds. CPU 0's six O2 child runs each had
16/16 positive blocks. CPU 7's three runs had positive/negative/zero block counts
0/13/3, 0/16/0 and 0/16/0. All reported zero migrations. The O2 CPU 0 to CPU 7 to
CPU 0 crossover therefore changed the sign and classification without changing
the Hide setting. Parent diagnostics changed sign too; this is not solely a forked
child effect. Selecting CPU 7 is not a validated detection fix.
The additional CPU 0 runs also include a negative parent diagnostic, so the observed
CPU effect is not a guarantee that every parent or child run on a given CPU has
the same sign. Their child block counts were 14/2/0, 16/0/0 and 16/0/0.

APK SHA-256 provenance:

- Original trace: `c3b547e27a8ed6331bcf7bf54e5f2994d2708dde2b9e5aff1e1a2ec7ede3cac8`.
- O2 CPU 0: `0f3dc7c4bd0459280c804a07f3d96638fa06f83fc5944b4898deaad0c34262bc`.
- O2 CPU 7: `06b8f3a04ea9202809e98eb6f3710f4b4b9f6a3c7327aafcea448219afd66311`.

On-device APK hashes were verified after installations. The O2 variants were built
from `ad14ebe0728c`; the older trace APK has a different revision, so its comparison
with O2 is not a whole-application single-variable optimization experiment. The two
O2 variants and the CPU 0 reinstall provide the stronger CPU crossover control.
Experiment-only optimization and CPU-selection source changes were reverted.
The original trace APK was restored with data preserved and its on-device hash
reverified. A final strict two-scan acquisition test passed with fresh parent/child
PIDs 29604/29622, CPU 0, paired medians 260/468 ns, 512 pairs and no migrations.

A fresh installed standalone PoC sample (parent PID 18408) accepted 512 pairs with
zero within-pair migrations, paired median -1 ns, and A slower on 205/512 pairs.
Its header reported entry CPU 5, but this path does not pin affinity and cannot
prove a single CPU throughout the sample. Its O2 parent-only implementation is
not interchangeable with Duck's pinned child. The screenshot's older PoC sample
must not be treated as a simultaneous same-CPU control.

These results demonstrate fresh-process timing instability and CPU-dependent sign,
not stale Zygote reuse in these successful runs. They do not resolve the historical
startup failure or establish a Hide-OFF false-positive rate: Hide remained enabled.
Within-run block agreement does not establish kernel causation or cross-CPU
calibration. A positive zero-boundary result cannot by itself establish hiding;
a negative result cannot exclude it. The exact modified kernel source and matched
CPU/kernel OFF/ON controls remain necessary to attribute the changed costs.

- Observable signal: 512 alternating AB/BA timings in the actual preload parent, after 32 warmup pairs and a disposable-child preflight, before the full AVC workload. A is the deliberately invalid type `u:r:__selinux_hide_probe_invalid__:s0`; B changes only its first byte to a newline. Every write must fail with EINVAL. `CLOCK_MONOTONIC_RAW` brackets each write separately; even-sized medians use the lower-middle element `(n - 1) / 2`. PID, observed CPU endpoints, paired median, A-slower count and sixteen ordered block medians are retained. The later pinned child's independent timings and counters remain diagnostic; partial samples retain medians without becoming a completed measurement.
- Producing subsystem: App Zygote preload, procfs attr/current, the SELinux LSM context parser and scheduler/clock observations.
- Mechanism: equal-length invalid-type and newline-prefixed writes exercise different stock paths; an altered dual-policy parser can change their relative cost. EINVAL controls, unchanged parent identity, 512 complete same-observed-CPU pairs and block consistency limit which samples expose a direction. They do not attribute its cause.
- References: [ZygotePreload API](https://developer.android.com/reference/android/app/ZygotePreload); ACK [android13-5.15-2025-01_r1 hooks.c](https://android.googlesource.com/kernel/common/+/refs/tags/android13-5.15-2025-01_r1/security/selinux/hooks.c) (`selinux_setprocattr`), and the KernelSU source revision linked below. The stock source converts A before credential allocation but skips conversion for B, so no timing-sign guarantee follows from these paths.
- Applicability: API >=29, application UID >=10000, app_zygote context with a field-bounded optional MLS category suffix, readable enforcing state and EINVAL controls. Collection changes no affinity; sampled endpoints must remain on the entry CPU. The cited GKI 5.15 comparison and device measurements do not certify other OEMs, kernel revisions or CPU classes.
- Visibility limits: scheduling, power state, caching and OEM policy/implementation can change costs. Sampled CPU endpoints cannot observe a migration away and back between reads. The synchronous parent syscall has no interruptible timeout; a successful child preflight cannot prove identical handling in every modified kernel. AVC counters and timing share a carrier and are not independent root evidence.
- Result states: positive direction, negative direction, inconclusive, unavailable; all are informational. Missing and legacy parent records cannot become measured negatives. Later child counter failures retain the separate completed parent evidence.
- Provenance: [GKI 5.15 hooks.c](https://github.com/aosp-mirror/kernel_common/blob/android13-5.15-2025-01_r1/security/selinux/hooks.c#L6542-L6684) first checks PROCESS__SETCURRENT. A fails during the invalid-type SID conversion, while B skips conversion then runs prepare_creds and abort_creds because its SID is zero; [GKI 5.15 cred.c](https://github.com/aosp-mirror/kernel_common/blob/android13-5.15-2025-01_r1/kernel/cred.c#L255-L303) shows allocation, copying and LSM preparation. [KernelSU #3877 / 2697f36f](https://github.com/tiann/KernelSU/blob/2697f36fc8ec10ab73e97ec1724e0f3212116ba2/kernel/feature/selinux_hide.c#L232-L310) retains the early AVC check while [its dual-policy parser](https://github.com/tiann/KernelSU/blob/2697f36fc8ec10ab73e97ec1724e0f3212116ba2/kernel/feature/selinux_hide.c#L603-L768) duplicates the input and resolves both sets of user, role and type symbols. The invalid-type candidate fails before MLS and SID registration.
- PoC verification: controlled physical-device Hide OFF/ON measurements with the standalone preload-parent PoC previously produced six valid OFF runs (paired medians −157 to −53 ns) and seven valid ON runs (+53 to +157 ns). Each run accepted 512 pairs without CPU migration; 94/96 OFF blocks were negative and 109/112 ON blocks were positive. These data validate that PoC on the tested configuration, **not** the Duck disposable-child collector or its end-to-end detection rate.
- Duck physical-device follow-up (2026-10-20, earlier failing installation): repeated scans with hiding enabled frequently returned **no timing measurement**. The dedicated App Zygote carrier binding dies before replying; controlled attr/current writes become unsupported, AVC counters remain uncollected, and the timing row reports `Timing unavailable` with `0/0` pairs, `N/A` medians and no parent sample. System logs for a reproduced failure show `ZygoteStartFailedEx: Error connecting to zygote`, caused by `java.io.IOException: Connection refused` while `ZygoteProcess.openZygoteSocketIfNeeded` tried to connect. This is an observed end-to-end **missed detection / false-negative coverage failure**, not evidence that A−B is zero or that hiding is absent. The underlying reason for the rejected Zygote socket connection and an empirical miss rate remain unverified.
- Interpretation: the current consistency gates above classify timing direction only. Incomplete or malformed parent samples cannot establish a direction; missing/legacy parent records are unavailable. A failure in the later AVC child does not erase a completed parent sample. Positive and negative directions are informational and cannot establish hiding or a clean environment.
- Limitations: the 16 blocks all come from one child in one retained preload; they are not 16 independent carriers. Stock GKI does not guarantee negative timing, because the relative costs of SID parsing vs credential construction vary with caches, scheduler, CPU and OEM. This finding is a conditional and device-calibrated anomaly, NOT direct proof of KernelSU/root. The AVC and timing rows share the same sample/mechanism and are not independent detections.
- Collection regression checks (2026-10-20): failed or incomplete disposable-child runs skip the optional parent diagnostic rather than replaying the failing syscalls in the carrier. An affinity change after a complete timing run keeps all 512 pairs and medians through native/Kotlin/carrier serialization; the later counter failure is reported separately. Host regressions cover these cases; subsequent physical-device results and the remaining startup limitation are recorded below.

#### Physical-device collection retest after the fixes (2026-10-20)

The rebuilt original-package APK was installed and its on-device SHA-256 matched
`153a2e08446fbdf0437042e5ecc2780bb760c69856be7fafed17b9ea5d6fe74f`.
Two scans still returned unavailable: the framework tried to connect to an existing
`ChildZygoteProcess` and received `Connection refused`, without a new Duck preload trace.
This remains an original-package collection failure; the two code fixes alone did not
recover that system-side startup state. Why the original carrier first exited is unverified.

A same-code diagnostic build with a different application ID produced three fresh
preload parents, with distinct parent/child PIDs. The existing kernel `selinux_hide`
feature was enabled; neither it nor the application's hiding configuration was changed.

| Fresh preload | Child paired median A−B | Parent paired median A−B | Pairs per process | CPU migrations | AVC rounds |
| --- | --- | --- | --- | --- | --- |
| 1 | 573 ns | 624 ns | 512 | 0 | 4 |
| 2 | 677 ns | 625 ns | 512 | 0 | 4 |
| 3 | 990 ns | 573 ns | 512 | 0 | 4 |

All processes measured CPU 0. Each child had 16 positive block medians and a majority
of A-slower pairs (442, 480 and 478 of 512), so all three retained timing rows were
positive. A second scan of each carrier returned the same retained sample; these are
three independent preloads, not six independent measurements. Parent measurements
remained diagnostic only. This is a collection and retained-export control, not an
OFF/ON sensitivity study. The changed package/UID and possible per-package hook
differences prevent using its success to claim the original package's startup problem
is fixed. Temporary diagnostic packages were removed without clearing the original
application's data. A later package installation changed the original package's
installed APK hash after this test; results here apply to the verified hash above,
not to that subsequent installation.

#### Original-package trace build and strict retest (2026-10-20)

The trace APK kept application ID `com.eltavine.duckdetector`. Its installed SHA-256
was `c3b547e27a8ed6331bcf7bf54e5f2994d2708dde2b9e5aff1e1a2ec7ede3cac8`
before and after five force-stop/start rounds on the physical device. Each round
ran two scans. Instrumentation explicitly required complete child and parent
512-pair samples, valid child medians, zero child migrations and a positive timing
verdict; unavailable exports could not pass. All ten scans passed. Each round
created a distinct preload parent and child; its second scan reused that snapshot.

| Round | Parent PID | Child PID | Child paired median A−B (ns) | Parent paired median A−B (ns) |
| --- | --- | --- | --- | --- |
| 1 | 10276 | 10296 | 834 | 573 |
| 2 | 10542 | 10568 | 833 | 573 |
| 3 | 11159 | 11178 | 573 | 573 |
| 4 | 11509 | 11528 | 625 | 573 |
| 5 | 11757 | 11779 | 573 | 521 |

All five children collected four AVC rounds and 16 positive timing blocks on CPU 0;
both parent and child had zero migrations. Each service connected and returned its
Binder snapshot. A transient framework `Connection refused` retry preceded successful
preload startup, so that line alone does not establish a failed collection.
Logging covers bind callbacks, cancellation/cleanup, service transactions, preload
entry and child/parent collection boundaries, outside the measured write loops.

This does not prove recovery of the earlier failing state: the package's observed
UID changed from 10527 during the refused cached-carrier runs to 10625 before this
retest. This testing did not rename or uninstall the original package, clear its
data, reboot, or change hiding settings. UID and APK remained unchanged during the
five rounds. The old carrier's initial death and the reason its stale framework
state persisted remain unverified. These are five successful independent preloads,
not an OFF/ON study or proof that missed detections are eliminated.

### Controlled attr/current recognition and ordinary-app timing

#### PoC-parent parity and CPU-dependent counterexample (2026-10-21)

The original package was updated in place (UID 10625 retained; no data clear,
package rename, Hide toggle or reboot). The rebuilt native parent collector used
the standalone PoC's unpinned parent, B/A preflight, O2 code generation, RAW-clock
write bracketing, 32 warmup pairs, 512 alternating AB/BA pairs and lower paired
median. Child timing remained separately pinned to CPU0 and diagnostic only.

On the physical device with the locally modified kernel, a complete parent sample
on CPU1 reported A=2864 ns, B=2657 ns, paired A−B=+209 ns (403/512 A slower,
16/16 positive blocks). Fresh parent runs on CPU1 then yielded +312 ns and
+261 ns; a CPU2 run gave +260 ns with one migrated pair (511/512 accepted,
invalid for classification). The pinned child stayed positive. The unchanged
standalone PoC, launched as its own fresh App Zygote, reported −52 ns on CPU5
and −261 ns on CPU3, both with 512/512 accepted pairs and zero migrations.
The latter CPU3 run measured median A=937 ns and B=1250 ns. Device CPU maximum
frequencies place CPU0–2 at 2016 MHz, CPU3–6 at 2803.2 MHz and CPU7 at
3187.2 MHz. This is a direct opposite-sign result across CPU performance
classes, not a demonstrated arithmetic or parent/child PID decoding error.

**Root cause and in-place correction:** the first attempted PoC alignment still
ran the full AVC disposable child BEFORE measuring the preload parent. This
included 32,768 counted writes and the child's own pinned timing, which changed
the workload/scheduler state before the parent sample. In a diagnostic build
that measured the parent first, independent parents on CPU7 and CPU4 both
reported paired A−B=−52 ns (512 pairs, zero migrations), matching the standalone
PoC. The final implementation adds a lightweight disposable child *before*
the parent, verifying carrier identity, enforcing state, same-FD B/A EINVAL
rejections and unchanged context. On success the native parent collects its
PoC-equivalent 512 pairs *before* the full AVC workload; failure, timeout,
seccomp trap, malformed reply or identity change cannot authorize a parent
measurement. The full AVC child still runs afterward and an invalid result
cannot contribute a timing verdict.

Four successive in-place physical-device runs of that final safe ordering
each created a fresh preload parent (PIDs 2687, 3153, 3453, 3723), sampled
CPU7 without migration, retained 512/512 pairs with paired A−B=−52 ns and
passed the instrumentation assertion requiring a NEGATIVE timing verdict.
The original application ID and UID 10625 remained unchanged; no data clear,
Hide toggle or reboot occurred. At that revision, Danger still applied to a positive complete
PoC-compatible parent median, and the pinned child's timing was diagnostic only.
Host JVM and native regression tests cover malformed/failed controls and
positive-child/negative-parent conflict. This resolves the reproduced in-place
false positive in these tests, not all possible CPU/load combinations. The
previous CPU0–2 positive measurements remain a documented counterexample;
matched per-CPU Hide OFF/ON controls and the exact modified-kernel diff are
still needed to establish generalizable detection specificity.


- Observable signal: repeated candidate-context refusal classes with preceding/following malformed and stock controls in the app_zygote child, plus the existing ordinary-app paired timing samples.
- Producing subsystem: procfs and SELinux context conversion/permission checks; the capability owns controlled writes, while this feature owns ordinary-app timing and evidence interpretation.
- Mechanism: only a complete controlled result with two issued EACCES refusals classifies a candidate as recognized. Repeated EINVAL only says the tested label was not recognized through this path. Timing compares A (the running context) and B (equal length with leading newline), requiring matching EACCES refusals; a payload-sensitive difference may reflect extra processing, scheduling, auditing or a hook. A timing threshold is not an architectural guarantee.
- References: Android Common Kernel [hooks.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/hooks.c) (`selinux_setprocattr`); capability/selinuxpolicy/EVIDENCE.md for additional ACK/AOSP controls and version-matched source; KernelSU [df03912](https://github.com/tiann/KernelSU/commit/df03912f70d92ff2aa9762ef82d607033d37e1da), [parent ab23091](https://github.com/tiann/KernelSU/blob/ab23091edfeddc774e1e880b0919b211808a193e/kernel/feature/selinux_hide.c), [3f388ef](https://github.com/tiann/KernelSU/commit/3f388ef137c78e1ca0c92c0ada3b8717cdcc4302) and [a810677](https://github.com/tiann/KernelSU/commit/a810677b847ba564c5f9d3fa0fbabe54794b8eef).
- Applicability: determined by source mechanisms and runtime controls, not package or KernelSU version strings. SELinux hiding is optional; a hidden backup policy can suppress recognized live types. Source-derived coverage is separated below; it has not been established by paired device measurements.
- Visibility limits: a failed carrier, SETCURRENT denial, open error or missing control cannot become a positive or negative integrity finding. Legacy uncontrolled records are informational. A stable timing difference does not prove a hook or identify KernelSU; earlier hook implementations can have no A/B difference. Shared SELinux mechanisms are not independent root indicators.
- Result states: context recognized, tested contexts not recognized, permission limited, unsupported, unavailable, inconclusive (typed as `SelinuxProcAttrCurrentVerdict`); experimental timing candidate, no reproducible asymmetry, unavailable.
- Interpretation: a controlled positive context-recognition result remains a warning. A reproducible ordinary-app timing candidate is Danger in the overall card, method row and impact text, reflecting a strong device-validated side-channel anomaly (Hide ON/OFF/ON on the validation device), not universal KernelSU identification or root proof. Existing independent Danger findings retain verdict precedence; the timing Danger must not be masked by an unrelated warning. No negative observation implies absence of KernelSU or policy modifications: "tested contexts not recognized" and every failed collection state add one informational impact line that says so, and the raw per-write record stays in the method row.

| KernelSU source interval / configuration | Source-derived expectation for retained probes |
| --- | --- |
| Hiding disabled | Live root contexts may be recognized by existing context queries and controlled writes. A valid context still does not identify the installed tool. |
| Hiding enabled, before `3f388ef` adds the attr hook | Original attr/current conversion can expose live-valid candidates while selinuxfs queries answer against the backup. Controlled writes can support recognition. |
| `3f388ef` through the parent of `a810677` | Backup validation hides added root contexts. The existing two-round SID-table registration experiment targets the unsynchronized context-query/attr registration discrepancy. |
| `a810677` through `ab23091`, hiding enabled | Synchronization removes that SID-table signature and backup validation hides added contexts. Ordinary-app SETCURRENT denial occurs before payload parsing. No reliable coverage is claimed for this gap. |
| `df03912`, hiding enabled | A stock-valid A reaches backup parsing before original SETCURRENT refusal; leading-newline B skips parsing. Existing timing can seek this difference, but source ordering does not establish a measurable or unique signature. |

The intervals describe the cited source paths, not all releases, forks, backports or future changes.
Other root probes in the repository retain their own contracts; package visibility, seccomp-blocked
supercalls and manager inotify behavior do not close this coverage gap. Draft validation must
record Android/API, kernel revision/configuration, ABI, enforcing state, hiding setting, raw control
and candidate errors, child outcome and preload capture age on each stock/modified device.

### Status mmap ABI conformance

- Observable signal: a granted two-page shared mapping, shared mapping at page offset 1, writable private mapping, or mprotect adding write permission to a read-only one-page private baseline on the status node.
- Producing subsystem: selinuxfs's `sel_mmap_handle_status`, observed through the selinuxpolicy capability's app_zygote carrier.
- Mechanism: the reviewed upstream handler requires one page at offset 0, rejects `VM_WRITE`, and clears `VM_MAYWRITE`. The private baseline preserves `VM_MAYWRITE` through VFS setup so the final mprotect request can examine the handler's clearing behavior. A shared baseline on an `O_RDONLY` descriptor would lose that flag before the handler and cannot test this constraint.
- References: ACK [5.10 selinuxfs.c](https://android.googlesource.com/kernel/common/+/a3431a2d02cd16bb212f7839cfa0934ce2a367ff/security/selinux/selinuxfs.c), [6.1 selinuxfs.c](https://android.googlesource.com/kernel/common/+/31addbff5e86095b5ee63a5d6446d7e76000bbc0/security/selinux/selinuxfs.c), and [6.1 mmap.c](https://android.googlesource.com/kernel/common/+/31addbff5e86095b5ee63a5d6446d7e76000bbc0/mm/mmap.c); the capability evidence record pins the mprotect, remapping and SELinux permission sources. Discovery only: [KernelPatch selinux_hide.c](https://github.com/bmax121/KernelPatch/blob/f36f3d1377004871f8c964f7cd3276712eeba943/kernel/patch/common/selinux_hide.c). No code is copied from it.
- Applicability: where the app_zygote carrier starts and can reach the status node, with device mapping behavior matching the reviewed ACK contract. Sizes and offsets use the runtime page size. Vendor differences require device validation.
- Visibility limits: unavailable open/baseline mapping is not negative evidence. An incomplete run without a grant is inconclusive; a grant reported before later child failure remains positive evidence. A conformant replacement handler, other hiding mechanisms, and rejections by other kernel or permission checks are not excluded by a negative observation.
- Result states: ABI violation, no violation observed, unavailable, inconclusive. A violation can coexist with an incomplete request set and a recorded failure reason.
- Interpretation: a confirmed ABI violation raises the method row and SELinux card to danger, even when later requests are unevaluated. Details name the granted requests and explain any incomplete request set. A completed negative run is labeled "No violation observed"; unavailable and inconclusive rows stay informational. This is evidence of mapping behavior, not proof of a specific modification. No granted mapping is dereferenced.

## Known gaps

- The policy notes pick their severity by matching the note text; see docs/architecture/follow-ups.md.
