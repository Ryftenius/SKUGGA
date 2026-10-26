#pragma once

#include "Core/runner_core.h"

namespace skugga::injector
{
    const SKUGGA_IPC_HOOK_POLICY_RULE *FindCliRule(const ServerContext &ctx,
                                                   const SKUGGA_IPC_HOOK_EVENT &eventRecord) noexcept;
    DWORD CliReadyMaskForPolicy(const ServerContext &ctx) noexcept;
    bool RuleApiIs(const SKUGGA_IPC_HOOK_POLICY_RULE &rule, const char *apiName) noexcept;
    const char *HookActionName(UINT32 action) noexcept;
    bool CliEventsEquivalentForRepeat(const SKUGGA_IPC_HOOK_EVENT &left, const SKUGGA_IPC_HOOK_EVENT &right) noexcept;
    bool ShouldPrintRepeatMilestone(UINT32 previous, UINT32 repeat) noexcept;
    bool ApplyCliRepeatAnnotation(ServerContext &ctx, SKUGGA_IPC_HOOK_EVENT &eventRecord) noexcept;
    bool SameDirectSyscallFold(const CliDetectionFoldState &fold, const SKUGGA_IPC_HOOK_EVENT &eventRecord) noexcept;
    bool ShouldPrintFoldedDirectSyscallDetection(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    bool ShouldPrintCliEvent(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    bool IsCliDetectionEvent(const SKUGGA_IPC_HOOK_EVENT &eventRecord) noexcept;
    bool IsSmartManagedEvent(const ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord) noexcept;
    bool ShouldSuppressRawForSmart(const ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord) noexcept;
    void PrintCliStack(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    void PrintCliStackAlways(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord, UINT32 limit);
    void FormatHexSample(const SKUGGA_IPC_HOOK_EVENT &eventRecord, char *out, std::size_t outChars,
                         UINT32 maxBytes) noexcept;
    void PrintCliDetectionEvent(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    void PrintCliDetectionFoldSummary(ServerContext &ctx);
    void PrintCliRegisters(const ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    void PrintCliNtEvent(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
    void PrintCliGenericEvent(ServerContext &ctx, const SKUGGA_IPC_HOOK_EVENT &eventRecord);
} // namespace skugga::injector
