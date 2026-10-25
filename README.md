***SKUGGA*** is a Windows userland **process-instrumentation** framework & tool designed for streamlined process API-hooking and quick triage. SKUGGA can launch a process and intercept its API calls without using debugger-API's via an injected DLL, that can be loaded in two ways (LoadLibrary & manual-mapping). It can automatically arm Nt*, module, Winsock and VEH hook surfaces before user-code starts. It streams structured telemetry that exposes & explains behaviour: API hits, clalers, stack/register context, memory changes, direct-syscalls and internal metadata.

![Research-backed Windows instrumentation workflow matrix](Docs/media/tooling-comparison.png)

Sources: S1 [captures](#api-observation), [CLI tests](Scripts/test_cli_syntax.ps1), [runtime tests](Scripts/test_internal_telemetry.ps1) · S2 [help](Injector/Core/runner_help.cpp), [parser](Injector/Policy/option_parsing.cpp) · [F1 frida-trace](https://frida.re/docs/frida-trace/) · [F2 Frida API](https://frida.re/docs/javascript-api/) · [D1 drwrap](https://dynamorio.org/page_drwrap.html) · [D2 drcallstack](https://dynamorio.org/page_drcallstack.html) · [D3 memory trace](https://github.com/DynamoRIO/dynamorio/blob/master/api/samples/memtrace_simple.c) · [X1 breakpoints](https://help.x64dbg.com/en/latest/commands/conditional-breakpoint-control/) · [X2 call stack](https://help.x64dbg.com/en/latest/gui/views/CallStack.html) · [X3 assembler](https://help.x64dbg.com/en/latest/commands/misc/asm.html) · [X4 tracing](https://help.x64dbg.com/en/latest/introduction/ConditionalTracing.html)

## DOCUMENTATION

- [Developer guide: SDK, integration, diagnostics, and releases](Docs/DEVELOPMENT.md)

## REQUIREMENTS

Windows 10 22H2 or higher, 64-bit, with Visual Studio 2022+ and the MSVC C++ toolchain.

Release 1.0.1 validation: 48 x64 verifier cases, 16 Win32 cases, 13 packet-boundary
checks per architecture, and signed-package smoke/architecture-handoff checks passed.

### API observation

~~~powershell
sk run .\bin\Release\x64\SkuggaTestTarget.exe --api NtQueryInformationProcess --timeout 10s
~~~

~~~text
[skugga:startup] target pid=23440 path=.\bin\Release\x64\SkuggaTestTarget.exe gate=1 guarded=0 injection=loadlibrary
[skugga:ready] pid=23440 update=0x0000000D active=0x0000000D components=ipc,nt,ki
[skugga] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x2173E args=[0xFFFFFFFFFFFFFFFF,0x34,0xDA3F2FF300,0x8]
[skugga] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x8A9AE args=[0xFFFFFFFFFFFFFFFF,0x25,0xDA3F2FF3D0,0x40]
[skugga:result] exit=0x00000000 events=25 suppressed=21
~~~

### Stacks, symbols, and registers

~~~powershell
sk run .\bin\Release\x64\SkuggaTestTarget.exe --api NtQueryInformationProcess --stack --registers --symbols --timeout 10s
~~~

Excerpt from the first call; additional frames and the second call are omitted:

~~~text
[skugga] NtQueryInformationProcess hit status=0x00000000 caller=KERNELBASE.dll+0x2173E args=[0xFFFFFFFFFFFFFFFF,0x34,0xB2447AF4A0,0x8]
    regs rip=0x7FF9E7BD173E rsp=0xB2447ADF80 rbp=0xB2447AE5B0 rax=0x0 rbx=0x7FF9E7BD173E rcx=0xFFFFFFFFFFFFFFFF rdx=0x34 rsi=0xB2447AE4E0 rdi=0xB2447AEDF0
         r8=0xB2447AF4A0 r9=0x8 r10=0x7FF9D7030000 r11=0x7FF9D704D95B r12=0x8 r13=0x0 r14=0x0 r15=0xB2447AF4A0 eflags=0x202
    #00 [system]   KERNELBASE.dll!GetProcessMitigationPolicy+0x4E
    #01 [system]   ws2_32.dll!getnameinfo+0x1BCA
    #02 [system]   ws2_32.dll!getnameinfo+0x589
    #03 [system]   ws2_32.dll!WSASocketW+0xAC3
~~~

SKUGGA frames are hidden from normal console and folded stack views.
**--include-internals** restores those frames and machinery records.
Raw diagnostic files preserve original events either way. Register values remain
the actual captured values; frame filtering does not rewrite registers or target
execution. Matching PDB availability determines symbol resolution. These captures
used the local Release directory as _NT_SYMBOL_PATH.

### Deny policy

~~~powershell
sk run .\bin\Release\x64\SkuggaTestTarget.exe --api NtQueryInformationProcess --deny --timeout 10s
~~~

~~~text
[skugga] NtQueryInformationProcess denied status=0xC0000022 caller=KERNELBASE.dll+0x2173E args=[0xFFFFFFFFFFFFFFFF,0x34,0xA449DDF3C0,0x8]
[skugga] NtQueryInformationProcess denied status=0xC0000022 caller=KERNELBASE.dll+0x8A9AE args=[0xFFFFFFFFFFFFFFFF,0x25,0xA449DDF490,0x40]
[skugga:result] exit=0x00000000 events=25 suppressed=21
~~~

This fixture tolerated the denied calls. Another target may behave differently.

### Slash syntax and raw syscall evidence

~~~powershell
sk run /api:NtQueryVirtualMemory,NtMapViewOfSection,NtProtectVirtualMemory /stack /raw /timeout:10s -- .\bin\Release\x64\SkuggaTestTarget.exe --cli-probe-direct-syscall
~~~

~~~text
[skugga:detection] direct-syscall source=NtProtectVirtualMemory page=0x1FA78450000 size=0x1000 stub=0x1FA78450000 ssn=0x1234  caller=KERNELBASE.dll+0xC0DCB sample=4C8BD1B8341200000F05C300000000000000000000000000000000000000000000000000000000000000000000000000...
[skugga:result] exit=0x00000000 events=40 suppressed=31
~~~

The fixture deliberately creates a recognizable syscall byte sequence. This
demonstrates recognition, not malicious intent or successful syscall execution.
Raw mode emitted no protect-folding startup notice.

Instrumentation-owned VirtualQuery calls are internally scoped. Unreadable
regions are skipped within the scanner's existing 64 KiB address-coverage bound.

### Behavior folding

~~~powershell
sk run .\bin\Release\x64\SkuggaTestTarget.exe --behavior --timeout 10s
~~~

~~~text
[skugga:result] exit=0x00000000 events=110 suppressed=51
[skugga:behavior] final summary
  scope       targets=1 regions=10 protect_groups=13 thread_starts=1 handles=0
[skugga:target] self  risk=rwx
  memory      allocs=13 total=2.71MB pages=695 maps=5 mapped=2.72MB regions=10 protects=38 queries=0 query_info=0B reads=0 read=0B writes=0 written=0B
  activity    process_opens=0 thread_opens=0 rwx=2.72MB threads=1 apc=0
~~~

Risk labels summarize properties such as executable writable memory; they are
not malware verdicts. Unobserved calls and unsupported paths remain unknown.

### Regression checks

~~~powershell
.\Scripts\test_cli_syntax.ps1 -BinaryPath .\bin\Release\x64\SkuggaRunner.exe
.\Scripts\test_internal_telemetry.ps1
~~~

~~~text
18 CLI syntax cases passed
Owned runtime probe passed: include-internals=False internal-frames=0
Owned runtime probe passed: include-internals=True internal-frames=18
~~~

The syntax suite covers help, version, selectors, slash options, compatibility,
ordering, and invalid inputs without launching a target. The runtime suite uses
the owned syscall fixture, verifies detection survives both visibility settings,
and rejects the folding notice in raw mode. This is not exhaustive validation
of every hook, loader, mitigation, or architecture.

## CLI QUICK REFERENCE

| Purpose | Current syntax |
| --- | --- |
| Observe APIs | --api Name or --api A,B; repeatable |
| Observe categories | --group memory or --group loader,network |
| Stacks and symbols | --stack --symbols |
| NT register snapshots | --registers |
| Deny NT calls | --deny |
| Suppress individual events | --quiet |
| Fold behavior / include raw events | --behavior / --raw |
| Include SKUGGA frames and machinery | --include-internals |
| Select loader | --loader standard or --loader manual |
| Bound target lifetime | --timeout 10s |
| Disable the launch gate | --no-launch-gate |
| Write diagnostics | --debug |

**--stack**, **--registers**, **--deny**, and **--quiet** apply across the command.
Registers and deny require NT-only selections.

Recognized slash switches accept both /api:Name and /api Name forms.
Place -- before the target to pass its following arguments literally:

~~~powershell
sk run /group:network /timeout:10s -- .\owned-target.exe /its-own-option
sk help
sk help hooks
sk groups
sk /version
~~~

## SDK INTEGRATION

The public protocol is **SKUGGA IPC**. Constants and types use **SKUGGA_IPC_***;
enum values use **SkuggaIpc***. The rename preserves packet layouts, magic,
protocol version 3, and numeric command values. Source consumers must update
their identifier names.

- [Packet ABI](SDK/include/skugga/skugga_ipc.h): packets, policies, batches, readiness.
- [VEH helpers](SDK/include/skugga/skugga_veh.h): in-process telemetry helpers.
- [Sample host](SDK/samples/host/SkuggaSdkHost.cpp): reference host and event consumer.

IPC-only hosts do not need an import library. Consumers of DLL exports define
IX_SKUGGA_IMPORTS and link SKUGGA.lib; this separate export macro is unchanged.

Hosts own pipe and target lifecycle, validate packets, acknowledge request
sequence numbers, and wait for required readiness before resuming. Core readiness
is 0x0000000D (IPC, NT, KI); module-aware runs may report 0x0000001D; full ABI
readiness is 0x0000001F. Readiness does not prove every API path was intercepted.

## COMPILATION AND INSTALLATION

Build with Visual Studio/MSBuild and the installed C++ toolset:

~~~powershell
msbuild .\VCXProj\SKUGGA.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\SkuggaRunner.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\SkuggaSdkHost.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\SkuggaTestTarget.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\VCXProj\SkuggaLaunchGateTarget.vcxproj /p:Configuration=Release /p:Platform=x64
~~~

Products are in **bin\Release\x64**. The runner defaults to version 1.0.1;
override it with /p:SkuggaVersion=1.0.2. Its generated build ID includes a
source digest and target architecture.

For direct CLI use, copy SkuggaRunner.exe as **skugga.exe** and optionally
**sk.exe**, with the matching SKUGGA.dll beside both. Add that directory to PATH.
The original runner name accepts --cli for CLI operation. Running the original
runner name without arguments enters the owned-test runner workflow.

Win32 projects also exist. Keep runner, DLL, and target architectures matched,
and preserve sibling x64/Win32 output directories for architecture handoff.
The fresh captures above validate x64 only.

Close instrumented targets before replacing a loaded DLL. Keep private PDBs
available on the symbol path when needed; avoid distributing them unintentionally.

## DIAGNOSTICS AND VALIDATION

**--debug** enables event JSONL, self-map TSV, summary, and runtime logs.
**--include-internals** controls console machinery visibility independently.
Original raw records remain in diagnostics even when console frames are filtered.
Keep bundles private: they may contain paths, addresses, arguments, and sampled
data.

The broader existing regression harness remains available:

~~~powershell
.\Scripts\run_skugga_tests.ps1 -Configuration Release
~~~

It was not rerun in full for this documentation update. Fresh validation is
limited to the five captures and two regression scripts above.

<p/>

## LICENSE

Copyright (c) RYFTENIUS. All rights reserved.

See [LICENSE](LICENSE) for the governing terms, defensive-use addendum, and
DSGL/export-control notice.
