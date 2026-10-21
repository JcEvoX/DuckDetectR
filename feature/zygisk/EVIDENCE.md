# Zygisk evidence record

Status: reviewed

The Zygisk detector asks whether code injected through zygote (Zygisk, Zygisk Next, ReZygisk, NeoZygisk) left traces in this app process. Strong traces point at injection; heuristic traces need corroboration.

## Signals

### Linker and namespace integrity

- Observable signal: whether dlopen, dlsym and dlclose resolve into the loader image, whether their entries branch straight out of it, and whether restricted-path libraries are loaded.
- Producing subsystem: the dynamic linker and this process's linker namespaces.
- Mechanism: injection frameworks hook the loader's entry points or load libraries from paths the app's namespace should not reach.
- References: bionic linker/linker_namespaces.h (is_accessible and isolated namespaces); kernel/common Documentation/filesystems/proc.rst for /proc/self/maps. Discovery only for the restricted path list.
- Applicability: the owning-image check on every ABI; the branch decoding on arm64 only.
- Visibility limits: an unreadable /proc/self/maps leaves the snapshot unavailable.
- Result states: bypassed, clean, unavailable.
- Interpretation: a linker hook or namespace bypass is a strong hit and danger.

### Memory map families

- Observable signal: suspicious executable mappings, deleted loaders, JIT cache drift, dirty system library pages, solist drift, atexit routing and heap entropy.
- Producing subsystem: this process's address space and the linker's soinfo list.
- Mechanism: an injected library that later unloads or hides still leaves mapping, dirty page or allocator residue.
- References: kernel/common Documentation/filesystems/proc.rst (maps and smaps fields). Discovery only for the per-framework residue patterns.
- Applicability: every ABI; heap entropy only where jemalloc state is readable.
- Visibility limits: each family is a heuristic with known benign causes.
- Result states: strong hit, heuristic hit, clean, unavailable.
- Interpretation: one heuristic family is a warning; multiple families escalate to danger for review, but do not establish injection. Loader-path residue seen through maps and descriptors is one family even when multiple files or descriptors match. JIT mapping structure, solist visibility, atexit ownership, dirty system code, thread names and heap entropy retain separate family identities. Different family identities do not prove statistical independence or exclude benign causes.

### Threads, descriptors and FD trap

- Observable signal: TracerPid, thread names, open descriptor targets, and whether a descriptor planted before fork is closed by an injection stack.
- Producing subsystem: procfs and zygote's fork path.
- Mechanism: Zygisk closes or reopens descriptors around specialization, and tracing tools set TracerPid.
- References: kernel/common Documentation/filesystems/proc.rst (status TracerPid, fd); frameworks/base core/jni/com_android_internal_os_Zygote.cpp for the specialization path. Discovery only for the FD trap's Zygisk-specific expectation.
- Applicability: the FD trap is skipped under a debugger or profiling agent.
- Visibility limits: debuggers and agents legitimately change descriptors and TracerPid. A detector binding the system stops before it connects, as it does to every service of the package when another of its processes fails to start, is bound once more; a second stop leaves the FD trap unavailable.
- Result states: FD trap hit, heuristic hit, clean, skipped.
- Interpretation: an FD trap hit is danger; thread and descriptor names are heuristics.

## Installed package paths and correlated residue

- Reference: [PackageManagerServiceUtils.getNextCodePath](https://android.googlesource.com/platform/frameworks/base/+/d1b7893669c02d6dc95c75133fa01eedc1d9fec6/services/core/java/com/android/server/pm/PackageManagerServiceUtils.java) uses two random 16-byte URL-safe Base64 installation tokens. Their characters are not evidence of an injection framework. Keyword classification shares the installed-path parser with Memory; evidence retains its original path and no WebView package is exempted.
- Regression: issue #400's WebView path contains `Riru` in the random suffix. Its APK/ODEX mappings and open APK descriptors must not produce a keyword hit. A real loader-path hit visible in both maps and FDs produces two diagnostic traces but only one heuristic family. Independent non-path mechanisms can still add families; direct strong hits and the FD trap keep their existing grading.
- Verification: `python3 feature/zygisk/data/src/test/python/test_loader_path_host_native.py` runs the production map and FD classifiers and family aggregation against synthetic fixtures. It covers ordinary WebView paths, real framework names, deleted libraries, non-executable mappings, repeated descriptors and independent JIT/atexit evidence. A device-specific reproduction still needs the exact WebView version and raw mapping/loader inventory.
