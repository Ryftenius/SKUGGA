#include "Core/runner_console.h"
#include "Core/cli_syntax.h"
#include "skugga_build_identity.h"
#include "Core/runner_help.h"
#include "Diagnostics/diagnostics.h"
#include "Ipc/pipe_server.h"
#include "Launch/injection.h"
#include "Mapper/mapper.h"
#include "Policy/option_parsing.h"
#include "Telemetry/cli_events.h"
#include "Telemetry/process_cache.h"
#include "Telemetry/process_symbols.h"
#include "Telemetry/smart_summary.h"

using namespace skugga::injector;

int wmain(int argc, wchar_t **argv)
{
    auto normalized = NormalizeSkuggaArgs(argc, argv);
    std::vector<wchar_t *> normalizedPointers;
    for (auto &arg : normalized)
        normalizedPointers.push_back(arg.data());
    argc = static_cast<int>(normalizedPointers.size());
    argv = normalizedPointers.data();
    std::wprintf(L"Ryftenius (R) SKUGGA, Version %ls\nBuild ID: %ls\nCopyright (C) 2026 Ryftenius.\nSPOOK\n\n",
                 SKUGGA_VERSION, SKUGGA_BUILD_ID);
    const int versionIndex = argc > 1 && wcscmp(argv[1], L"--cli") == 0 ? 2 : 1;
    if (argc > versionIndex &&
        (_wcsicmp(argv[versionIndex], L"--version") == 0 || _wcsicmp(argv[versionIndex], L"version") == 0 ||
         wcscmp(argv[versionIndex], L"-V") == 0))
    {
        return 0;
    }
    ConfigureConsoleColor(ConsoleColorMode::Auto);
    std::wstring baseDir = ModuleDirectory();
    std::wstring dllPath = baseDir + L"\\SKUGGA.dll";
    RunnerOptions options{};
    options.TargetPath = baseDir + L"\\SkuggaTestTarget.exe";

    const wchar_t *invokedName = argv[0];
    if (const wchar_t *slash = wcsrchr(invokedName, L'\\'))
    {
        invokedName = slash + 1;
    }
    const bool implicitCliMode = _wcsicmp(invokedName, L"skugga.exe") == 0 || _wcsicmp(invokedName, L"sk.exe") == 0 ||
                                 (argc > 1 && wcscmp(argv[1], L"run") == 0);
    const bool explicitCliMode = argc > 1 && wcscmp(argv[1], L"--cli") == 0;
    int cliStart = explicitCliMode ? 2 : 1;
    if (argc > cliStart && wcscmp(argv[cliStart], L"run") == 0)
        ++cliStart;
    if (implicitCliMode || explicitCliMode)
    {
        if (argc == cliStart + 1 && (wcscmp(argv[cliStart], L"hooks") == 0 || wcscmp(argv[cliStart], L"groups") == 0))
        {
            PrintHelpTopic(argv[cliStart]);
            return 0;
        }
        if (argc > cliStart && wcscmp(argv[cliStart], L"help") == 0)
        {
            PrintHelpTopic(argc > cliStart + 1 ? argv[cliStart + 1] : nullptr);
            return 0;
        }
        if (argc == cliStart || (argc == cliStart + 1 && IsHelpArgument(argv[cliStart])))
        {
            PrintUsage();
            return 0;
        }
        if (!ParseCliMode(argc, argv, cliStart, options))
        {
            return options.HelpRequested ? 0 : 2;
        }
    }
    else
    {
        for (int argIndex = 1; argIndex < argc; ++argIndex)
        {
            if (IsHelpArgument(argv[argIndex]))
            {
                PrintHelpTopic(wcscmp(argv[argIndex], L"help") == 0 && argIndex + 1 < argc ? argv[argIndex + 1]
                                                                                           : nullptr);
                return 0;
            }
            if (wcscmp(argv[argIndex], L"--verbose") == 0)
            {
                options.Verbose = true;
                continue;
            }
            if (wcscmp(argv[argIndex], L"--launch-gate") == 0)
            {
                options.LaunchGateMode = true;
                options.GuardedLaunchGate = true;
                continue;
            }
            if (wcscmp(argv[argIndex], L"--disable-lg") == 0 || wcscmp(argv[argIndex], L"--no-launch-gate") == 0)
            {
                options.LaunchGateMode = false;
                options.GuardedLaunchGate = false;
                continue;
            }
            if (wcscmp(argv[argIndex], L"--mm") == 0 || wcscmp(argv[argIndex], L"--manual-map") == 0)
            {
                options.ManualMap = true;
                continue;
            }
            if (wcscmp(argv[argIndex], L"--timeout") == 0 || wcscmp(argv[argIndex], L"--target-timeout") == 0)
            {
                if (argIndex + 1 >= argc)
                {
                    std::wprintf(L"[skugga] %ls requires a duration such as 15000, 30s, "
                                 L"2m, or none\n",
                                 argv[argIndex]);
                    return 2;
                }
                if (!ParseDurationMs(argv[++argIndex], options.ChildTimeoutMs))
                {
                    std::wprintf(L"[skugga] invalid timeout duration: %ls\n", argv[argIndex]);
                    return 2;
                }
                continue;
            }
            if (wcscmp(argv[argIndex], L"--no-color") == 0 || wcscmp(argv[argIndex], L"--no-colour") == 0 ||
                wcscmp(argv[argIndex], L"--color") == 0 || wcscmp(argv[argIndex], L"--colour") == 0 ||
                wcsncmp(argv[argIndex], L"--color=", 8) == 0 || wcsncmp(argv[argIndex], L"--colour=", 9) == 0)
            {
                if (!ParseColorMode(options, argv[argIndex]))
                {
                    return 2;
                }
                continue;
            }
            if (wcscmp(argv[argIndex], L"--pipe") == 0)
            {
                if (argIndex + 1 >= argc)
                {
                    std::wprintf(L"[skugga] --pipe requires a named-pipe path\n");
                    return 2;
                }
                (void)SetEnvironmentVariableW(SKUGGA_IPC_PIPE_NAME_ENV, argv[++argIndex]);
                continue;
            }
            if (!options.TargetSet)
            {
                options.TargetPath = argv[argIndex];
                options.TargetSet = true;
                continue;
            }

            std::wprintf(L"[skugga] unexpected argument: %ls\n", argv[argIndex]);
            return 2;
        }
        if (options.GuardedLaunchGate && !options.TargetSet)
        {
            options.TargetPath = baseDir + L"\\SkuggaLaunchGateTarget.exe";
        }
    }

    const std::wstring &targetPath = options.TargetPath;

    if (!FileExists(targetPath))
    {
        std::wprintf(L"[skugga] missing target: %ls\n", targetPath.c_str());
        return 2;
    }

    int architectureExitCode = 0;
    if (RelaunchForTargetArchitecture(argc, argv, targetPath, architectureExitCode))
    {
        return architectureExitCode;
    }
#if !defined(_WIN64)
    if (options.GuardedLaunchGate)
    {
        ColorPrintf(LogColor::Warning, "[skugga] guarded launch gate is unavailable on x86; "
                                       "using the suspended pre-entry gate\n");
        options.GuardedLaunchGate = false;
        if (!options.TargetSet)
        {
            options.TargetPath = baseDir + L"\\SkuggaTestTarget.exe";
        }
    }
#endif
    if (!FileExists(dllPath))
    {
        std::wprintf(L"[skugga] missing DLL: %ls\n", dllPath.c_str());
        return 2;
    }

    wchar_t existingPipeName[2]{};
    if (options.CliMode &&
        GetEnvironmentVariableW(SKUGGA_IPC_PIPE_NAME_ENV, existingPipeName, RTL_NUMBER_OF(existingPipeName)) == 0)
    {
        std::wstring cliPipe = BuildUniqueCliPipeName();
        (void)SetEnvironmentVariableW(SKUGGA_IPC_PIPE_NAME_ENV, cliPipe.c_str());
    }

    ServerContext ctx{};
    ctx.Verbose = options.Verbose;
    ctx.CliMode = options.CliMode;
    ctx.ResolveSymbols = options.ResolveSymbols;
    ctx.IncludeInternals = options.IncludeInternals;
    ctx.SymbolSearchPath = options.SymbolSearchPath;
    ctx.SmartMode = options.SmartMode;
    ctx.SmartRawEvents = options.SmartRawEvents;
    ctx.SmartStacks = options.SmartStacks;
    ctx.SmartStackFrameLimit = options.SmartStackFrameLimit;
    ctx.SmartAreas = options.SmartAreas;
    ctx.SmartSummaryIntervalMs = options.SmartSummaryIntervalMs;
    ctx.Conditions = options.Conditions;
    ctx.DebugDiagnostics = options.DebugDiagnostics;
    ctx.LaunchGateMode = options.LaunchGateMode;
    ctx.ChildTimeoutMs = options.ChildTimeoutMs;
    ctx.CliPolicy = options.CliPolicy;
    ctx.PipeName = EffectivePipeName();
    const bool remoteSmart = (ctx.SmartAreas & kSmartAreaRemote) != 0;
    ReserveServerContextStorage(ctx, remoteSmart);
    if (ctx.DebugDiagnostics && !OpenDiagnostics(ctx, baseDir))
    {
        CloseDiagnostics(ctx);
        return 2;
    }
    if (ctx.DebugDiagnostics)
    {
        (void)SetEnvironmentVariableW(L"SKUGGA_LOG_DIR", ctx.LogDir.c_str());
        (void)SetEnvironmentVariableW(L"SKUGGA_DISABLE_FILE_LOG", nullptr);
    }
    else
    {
        (void)SetEnvironmentVariableW(L"SKUGGA_LOG_DIR", nullptr);
        (void)SetEnvironmentVariableW(L"SKUGGA_DISABLE_FILE_LOG", L"1");
    }
    (void)SetEnvironmentVariableW(L"SKUGGA_RUNNER_OWNS_PIPE", L"1");
    if (options.GuardedLaunchGate)
    {
        (void)SetEnvironmentVariableW(L"IX_HOOK_LAUNCH_GATE", L"1");
    }
    else
    {
        (void)SetEnvironmentVariableW(L"IX_HOOK_LAUNCH_GATE", nullptr);
    }

    ctx.ReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ctx.ReadyEvent == nullptr)
    {
        ColorPrintf(LogColor::Error, "[skugga] CreateEvent failed gle=%lu\n", GetLastError());
        CloseDiagnostics(ctx);
        return 2;
    }

    HANDLE serverThread = CreateThread(nullptr, 0, PipeServerThread, &ctx, 0, nullptr);
    if (serverThread == nullptr)
    {
        ColorPrintf(LogColor::Error, "[skugga] server thread failed gle=%lu\n", GetLastError());
        CloseHandle(ctx.ReadyEvent);
        CloseDiagnostics(ctx);
        return 2;
    }

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring commandLine =
        options.CliMode ? BuildTargetCommandLine(targetPath, options.TargetArgs) : QuotePath(targetPath);
    const bool debugPreEntryManualMap = options.ManualMap && options.LaunchGateMode;
    const bool startSuspended = options.LaunchGateMode;
    const bool hideChildWindow = EnvironmentVariableEnabled(L"SKUGGA_TEST_NO_NEW_CONSOLE");
    if (hideChildWindow)
    {
        si.dwFlags |= STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }
    DWORD creationFlags = (hideChildWindow ? CREATE_NO_WINDOW : CREATE_NEW_CONSOLE) |
                          (startSuspended && !debugPreEntryManualMap ? CREATE_SUSPENDED : 0) |
                          (debugPreEntryManualMap ? DEBUG_ONLY_THIS_PROCESS : 0);
    UINT previousErrorMode =
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    BOOL created = CreateProcessW(targetPath.c_str(), commandLine.data(), nullptr, nullptr, FALSE, creationFlags,
                                  nullptr, options.CliMode ? nullptr : baseDir.c_str(), &si, &pi);
    (void)SetErrorMode(previousErrorMode);
    if (!created)
    {
        ColorPrintf(LogColor::Error, "[skugga] CreateProcess failed gle=%lu\n", GetLastError());
        ctx.Stop.store(true, std::memory_order_release);
        SKUGGA_SUPPORT::JoinStoppedPipeThread(serverThread);
        CloseHandle(serverThread);
        CloseHandle(ctx.ReadyEvent);
        CloseDiagnostics(ctx);
        return 3;
    }

    std::wprintf(L"[skugga:startup] target pid=%lu path=%ls gate=%u guarded=%u "
                 L"injection=%ls\n",
                 pi.dwProcessId, targetPath.c_str(), options.LaunchGateMode ? 1u : 0u,
                 options.GuardedLaunchGate ? 1u : 0u, options.ManualMap ? L"manual-map" : L"loadlibrary");
    ctx.ChildProcessId = pi.dwProcessId;
    ctx.ChildProcessHandle = pi.hProcess;
    if (debugPreEntryManualMap)
    {
        if (!skugga::mapper::PauseDebuggedChildAtEntrypoint(ctx, pi))
        {
            TerminateProcess(pi.hProcess, ERROR_DLL_INIT_FAILED);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            ctx.Stop.store(true, std::memory_order_release);
            SKUGGA_SUPPORT::JoinStoppedPipeThread(serverThread);
            CloseHandle(serverThread);
            CloseHandle(ctx.ReadyEvent);
            CloseDiagnostics(ctx);
            return 4;
        }
    }
    RefreshChildModules(ctx);
    if (ctx.DebugDiagnostics)
    {
        wchar_t logName[64]{};
        (void)StringCchPrintfW(logName, RTL_NUMBER_OF(logName), L"skugga-runtime-%lu.log", pi.dwProcessId);
        ctx.RuntimeLogPath = JoinPath(ctx.LogDir, logName);
        std::wprintf(L"[skugga] runtime log=%ls\n", ctx.RuntimeLogPath.c_str());
    }
    if (!startSuspended)
    {
        Sleep(500);
    }
    HostDebugLog(ctx, "created child pid=%lu suspended=%u launch_gate=%u guarded=%u mapper=%u", pi.dwProcessId,
                 startSuspended ? 1u : 0u, options.LaunchGateMode ? 1u : 0u, options.GuardedLaunchGate ? 1u : 0u,
                 options.ManualMap ? 1u : 0u);
    bool injected = options.ManualMap ? skugga::mapper::MapDllIntoChild(ctx, pi.hProcess, dllPath)
                                      : InjectDllIntoChild(ctx, pi.hProcess, dllPath);
    if (!injected)
    {
        DWORD injectionError = GetLastError();
        if (injectionError == ERROR_SUCCESS)
        {
            injectionError = ERROR_DLL_INIT_FAILED;
        }
        ColorPrintf(LogColor::Error, "[skugga] injection failed error=%lu (0x%08lX)\n", injectionError, injectionError);
        TerminateProcess(pi.hProcess, injectionError);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        ctx.Stop.store(true, std::memory_order_release);
        SKUGGA_SUPPORT::JoinStoppedPipeThread(serverThread);
        CloseHandle(serverThread);
        CloseHandle(ctx.ReadyEvent);
        CloseDiagnostics(ctx);
        return 4;
    }

    bool readyWaitCompleted = false;
    DWORD readyWait = WAIT_TIMEOUT;
    if (startSuspended && !options.GuardedLaunchGate)
    {
        readyWait = WaitForSingleObject(ctx.ReadyEvent, kReadyTimeoutMs);
        readyWaitCompleted = true;
        const DWORD readyMask = ctx.ReadyMask.load(std::memory_order_acquire);
        char components[64]{};
        FormatReadyComponents(readyMask, components, RTL_NUMBER_OF(components));
        TaggedPrintf(LogColor::Info, "[skugga:ready]", " wait=%lu mask=0x%08lX components=%s\n", readyWait,
                     static_cast<unsigned long>(readyMask), components);
        RefreshChildModules(ctx);
    }

    if (startSuspended)
    {
        DWORD previousSuspendCount = ResumeThread(pi.hThread);
        if (previousSuspendCount == static_cast<DWORD>(-1))
        {
            ColorPrintf(LogColor::Error, "[skugga] ResumeThread failed gle=%lu\n", GetLastError());
            TerminateProcess(pi.hProcess, ERROR_INVALID_STATE);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            ctx.Stop.store(true, std::memory_order_release);
            SKUGGA_SUPPORT::JoinStoppedPipeThread(serverThread);
            CloseHandle(serverThread);
            CloseHandle(ctx.ReadyEvent);
            CloseDiagnostics(ctx);
            return 4;
        }
        if (options.GuardedLaunchGate)
        {
            ColorPrintf(LogColor::Lifecycle, "[skugga] launch-gate child resumed previous_suspend_count=%lu\n",
                        static_cast<unsigned long>(previousSuspendCount));
        }
        else if (options.Verbose)
        {
            ColorPrintf(LogColor::Info, "[skugga] cli child resumed previous_suspend_count=%lu\n",
                        static_cast<unsigned long>(previousSuspendCount));
        }
    }

    if (!readyWaitCompleted)
    {
        readyWait = WaitForSingleObject(ctx.ReadyEvent, kReadyTimeoutMs);
        const DWORD readyMask = ctx.ReadyMask.load(std::memory_order_acquire);
        char components[64]{};
        FormatReadyComponents(readyMask, components, RTL_NUMBER_OF(components));
        TaggedPrintf(LogColor::Info, "[skugga:ready]", " wait=%lu mask=0x%08lX components=%s\n", readyWait,
                     static_cast<unsigned long>(readyMask), components);
    }

    DWORD childTimeout =
        options.ChildTimeoutMs != INFINITE ? options.ChildTimeoutMs : (options.CliMode ? INFINITE : 30000);
    DWORD childWait = WaitForSingleObject(pi.hProcess, childTimeout);
    if (childWait == WAIT_TIMEOUT)
    {
        ColorPrintf(LogColor::Warning, "[skugga] child wait timed out; terminating pid=%lu\n", pi.dwProcessId);
        TerminateProcess(pi.hProcess, WAIT_TIMEOUT);
        WaitForSingleObject(pi.hProcess, 5000);
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    // Child exit can precede rendering of the final telemetry packet. Join the
    // worker before reading its state or printing the result; allow normal EOF
    // first, with bounded cancellation for a stalled or never-connected client.
    if (WaitForSingleObject(serverThread, 5000) != WAIT_OBJECT_0)
    {
        ctx.Stop.store(true, std::memory_order_release);
        SKUGGA_SUPPORT::JoinStoppedPipeThread(serverThread);
        ColorPrintf(LogColor::Warning, "[skugga] telemetry drain incomplete; worker stopped\n");
    }
    TaggedPrintf(exitCode == 0 ? LogColor::Success : LogColor::Warning, "[skugga:result]",
                 " exit=0x%08lX events=%lu suppressed=%lu\n", exitCode,
                 static_cast<unsigned long>(ctx.HookEventCount.load(std::memory_order_acquire)),
                 static_cast<unsigned long>(ctx.SuppressedEventCount.load(std::memory_order_acquire)));
    ColorPrintf(LogColor::Lifecycle, "[skugga] launch-gate traps=%lu\n",
                static_cast<unsigned long>(ctx.LaunchGateTrapCount.load(std::memory_order_acquire)));
    if (ctx.DebugDiagnostics)
    {
        ColorPrintf(LogColor::Info, "[skugga] self-map entries=%zu\n", ctx.SelfMapEntries.size());
        std::wprintf(L"[skugga] diagnostics summary=%ls\n", JoinPath(ctx.RunDir, L"summary.txt").c_str());
    }

    CloseHandle(pi.hThread);

    PrintSmartSummary(ctx, true);
    if (options.CliMode)
    {
        PrintCliDetectionFoldSummary(ctx);
    }
    CloseCachedProcessHandles(ctx);
    CloseHandle(pi.hProcess);
    ctx.ChildProcessHandle = nullptr;
    CloseHandle(serverThread);
    CloseHandle(ctx.ReadyEvent);
    if (ctx.EventsFile != nullptr)
    {
        std::fflush(ctx.EventsFile);
    }
    if (ctx.SelfMapFile != nullptr)
    {
        std::fflush(ctx.SelfMapFile);
    }
    if (ctx.DebugDiagnostics)
    {
        WriteSummary(ctx, exitCode, childWait);
    }
    CloseDiagnostics(ctx);
    CleanupSymbols(ctx);

    DWORD finalReadyMask = ctx.ReadyMask.load(std::memory_order_acquire);
    if (options.CliMode)
    {
        const DWORD cliReadyMask = CliReadyMaskForPolicy(ctx);
        if ((finalReadyMask & cliReadyMask) != cliReadyMask)
        {
            return 5;
        }
        return static_cast<int>(exitCode);
    }

    bool ok = exitCode == 0 && ctx.HookEventCount.load(std::memory_order_acquire) != 0 &&
              ((finalReadyMask & SKUGGA_SDK_READY_CORE_MASK) == SKUGGA_SDK_READY_CORE_MASK);
    if (options.GuardedLaunchGate)
    {
        ok = ok && ctx.LaunchGateTrapCount.load(std::memory_order_acquire) != 0;
    }
    return ok ? 0 : 5;
}
