#include "nt.h"
#include "nt_methods.h"
#include "../include/native_peb.h"
#include "runtime/runtime_internal.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <utility>

#pragma intrinsic(_ReturnAddress)

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef PAGE_TARGETS_INVALID
#define PAGE_TARGETS_INVALID 0x40000000u
#endif

#ifndef PAGE_TARGETS_NO_UPDATE
#define PAGE_TARGETS_NO_UPDATE 0x40000000u
#endif

namespace IX_NT
{
    static NtHookInitFault g_LastNtHookInitFault{};

    static void ResetNtHookInitFault() noexcept
    {
        std::memset(&g_LastNtHookInitFault, 0, sizeof(g_LastNtHookInitFault));
        g_LastNtHookInitFault.Code = NtHookInitFaultCode::None;
    }

    static void CaptureFaultSample(const void *address, std::uint8_t sample[16]) noexcept
    {
        std::memset(sample, 0, 16);
        if (address == nullptr)
        {
            return;
        }

        __try
        {
            std::memcpy(sample, address, 16);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(sample, 0, 16);
        }
    }

    static void SetNtHookInitFault(NtHookInitFaultCode code, const char *functionName, void *address,
                                   void *redirectTarget = nullptr, std::uint32_t syscallIndex = 0) noexcept
    {
        ResetNtHookInitFault();
        g_LastNtHookInitFault.Code = code;
        g_LastNtHookInitFault.FunctionName = functionName;
        g_LastNtHookInitFault.Address = address;
        g_LastNtHookInitFault.RedirectTarget = redirectTarget;
        g_LastNtHookInitFault.SyscallIndex = syscallIndex;
        CaptureFaultSample(address, g_LastNtHookInitFault.Sample);
    }

    static bool ShouldEnableNtMemoryHooks() noexcept
    {
        char value[16]{};
        static constexpr IX_RUNTIME_INTERNAL::IxEncodedAnsiLiteral kEnvName{"IX_NT_HOOK_MEMORY", 0x83u};
        IX_RUNTIME_INTERNAL::IxScopedAnsiLiteral envName(kEnvName);
        DWORD read = GetEnvironmentVariableA(envName.c_str(), value, static_cast<DWORD>(RTL_NUMBER_OF(value)));
        if (read == 0 || read >= RTL_NUMBER_OF(value))
        {
            return false;
        }

        return lstrcmpiA(value, "1") == 0 || lstrcmpiA(value, "true") == 0 || lstrcmpiA(value, "yes") == 0 ||
               lstrcmpiA(value, "on") == 0 || lstrcmpiA(value, "enabled") == 0;
    }

    static bool IsNtMemoryHookName(const char *name) noexcept
    {
        if (name == nullptr)
        {
            return false;
        }

        return (std::strcmp(name, "NtAllocateVirtualMemory") == 0) ||
               (std::strcmp(name, "NtProtectVirtualMemory") == 0) ||
               (std::strcmp(name, "NtAllocateVirtualMemoryEx") == 0) ||
               (std::strcmp(name, "NtMapViewOfSection") == 0) || (std::strcmp(name, "NtMapViewOfSectionEx") == 0);
    }

    typedef struct _CLIENT_ID
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CLIENT_ID, *PCLIENT_ID;

    using NtCreateThread_t = NTSTATUS(NTAPI *)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                               PCLIENT_ID ClientId, PCONTEXT ThreadContext, PIX_INITIAL_TEB InitialTeb,
                                               BOOLEAN CreateSuspended);

    using NtCreateThreadEx_t = NTSTATUS(NTAPI *)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                                 POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                                 PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
                                                 SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

    using NtWriteVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                     SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

    using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

    using NtProtectVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                       ULONG NewProtect, PULONG OldProtect);

    using NtReadVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                    SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);

    using NtQueryVirtualMemory_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress,
                                                     ULONG MemoryInformationClass, PVOID MemoryInformation,
                                                     SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

    using NtQuerySystemInformation_t = NTSTATUS(NTAPI *)(ULONG SystemInformationClass, PVOID SystemInformation,
                                                         ULONG SystemInformationLength, PULONG ReturnLength);

    using NtCreateSection_t = NTSTATUS(NTAPI *)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                                POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                                ULONG SectionPageProtection, ULONG AllocationAttributes,
                                                HANDLE FileHandle);

    using NtTerminateProcess_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

    using NtOpenProcessToken_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                                   PHANDLE TokenHandle);

    using NtOpenThreadToken_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                                  PHANDLE TokenHandle);

    using NtOpenFile_t = NTSTATUS(NTAPI *)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                           POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
                                           ULONG ShareAccess, ULONG OpenOptions);

    using NtQueryInformationProcess_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                          PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                          PULONG ReturnLength);

    using NtQueryInformationThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                         PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                         PULONG ReturnLength);

    using NtSetContextThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PCONTEXT ThreadContext);

    using NtQuerySection_t = NTSTATUS(NTAPI *)(HANDLE SectionHandle, ULONG SectionInformationClass,
                                               PVOID InformationBuffer, ULONG InformationBufferSize,
                                               PULONG ResultLength);

    using NtQueryBootOptions_t = NTSTATUS(NTAPI *)(PVOID BootOptions, PULONG BootOptionsLength);

    using NtOpenProcess_t = NTSTATUS(NTAPI *)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                              POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

    using NtOpenThread_t = NTSTATUS(NTAPI *)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                             POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

    using NtDuplicateObject_t = NTSTATUS(NTAPI *)(HANDLE SourceProcessHandle, HANDLE SourceHandle,
                                                  HANDLE TargetProcessHandle, PHANDLE TargetHandle,
                                                  ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);

    using NtGetContextThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PCONTEXT ThreadContext);

    using NtSuspendThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    using NtResumeThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    using NtQueueApcThread_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1,
                                                 PVOID ApcArgument2, PVOID ApcArgument3);

    using NtAllocateVirtualMemoryEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                          ULONG AllocationType, ULONG PageProtection,
                                                          PVOID ExtendedParameters, ULONG ExtendedParameterCount);

    using NtMapViewOfSection_t = NTSTATUS(NTAPI *)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                                   ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
                                                   PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
                                                   ULONG Win32Protect);

    using NtMapViewOfSectionEx_t = NTSTATUS(NTAPI *)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                                     PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
                                                     ULONG AllocationType, ULONG Win32Protect, PVOID ExtendedParameters,
                                                     ULONG ExtendedParameterCount);

    using NtUnmapViewOfSection_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress);

    using NtUnmapViewOfSectionEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags);

    using NtQueueApcThreadEx_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine,
                                                   PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

    using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, HANDLE UserApcReserveHandle,
                                                    ULONG QueueUserApcFlags, PVOID ApcRoutine, PVOID ApcArgument1,
                                                    PVOID ApcArgument2, PVOID ApcArgument3);

    using NtOpenProcessTokenEx_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                                     ULONG HandleAttributes, PHANDLE TokenHandle);

    using NtOpenThreadTokenEx_t = NTSTATUS(NTAPI *)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                                    ULONG HandleAttributes, PHANDLE TokenHandle);

    using NtQuerySystemInformationEx_t = NTSTATUS(NTAPI *)(ULONG SystemInformationClass, PVOID InputBuffer,
                                                           ULONG InputBufferLength, PVOID SystemInformation,
                                                           ULONG SystemInformationLength, PULONG ReturnLength);

    static std::uint64_t PointerCodecCookie() noexcept
    {
        static std::uint64_t cookie = 0;
        if (cookie != 0)
        {
            return cookie;
        }

        LARGE_INTEGER counter{};
        (void)QueryPerformanceCounter(&counter);
        std::uint64_t value = static_cast<std::uint64_t>(counter.QuadPart);
        value ^= __rdtsc();
        value ^= reinterpret_cast<std::uintptr_t>(&cookie);
        value ^= static_cast<std::uint64_t>(GetCurrentProcessId()) << 23;
        value ^= static_cast<std::uint64_t>(GetCurrentThreadId()) << 7;
        value = (value << 19) | (value >> 45);
        cookie = value != 0 ? value : 0x71D15A5E5AFE1107ull;
        return cookie;
    }

    template <typename T> struct EncodedProc
    {
        std::uint64_t Encoded = 0;

        EncodedProc() noexcept = default;
        EncodedProc(std::nullptr_t) noexcept {}

        EncodedProc &operator=(std::nullptr_t) noexcept
        {
            Encoded = 0;
            return *this;
        }

        EncodedProc &operator=(T value) noexcept
        {
            Encoded = value == nullptr ? 0 : (reinterpret_cast<std::uint64_t>(value) ^ PointerCodecCookie());
            return *this;
        }

        T Get() const noexcept
        {
            return Encoded == 0 ? nullptr : reinterpret_cast<T>(Encoded ^ PointerCodecCookie());
        }

        explicit operator bool() const noexcept
        {
            return Get() != nullptr;
        }

        template <typename... Args> auto operator()(Args... args) const noexcept -> decltype(std::declval<T>()(args...))
        {
            T fn = Get();
            return fn(args...);
        }
    };

    // Minimal layout of SYSTEM_THREAD_INFORMATION as documented in ntdll symbols.
    // x64 natural alignment yields 80 bytes; x86 is not supported (IxSetNtHook
    // returns false on x86) so no 32-bit variant is needed.
    struct IxSystemThreadInformation
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
#if defined(_WIN64)
        ULONG Pad0;
#endif
        PVOID StartAddress;
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
        LONG Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        ULONG WaitReason;
#if defined(_WIN64)
        ULONG Pad1;
#endif
    };
#if defined(_WIN64)
    static_assert(sizeof(IxSystemThreadInformation) == 80, "IxSystemThreadInformation size mismatch");
#else
    static_assert(sizeof(IxSystemThreadInformation) == 64, "IxSystemThreadInformation size mismatch");
#endif

    inline constexpr ULONG kSystemProcessInformation = 5u;
    inline constexpr ULONG kSystemHandleInformation = 16u;
    inline constexpr ULONG kSystemKernelDebuggerInformation = 35u;
    inline constexpr ULONG kSystemExtendedHandleInformation = 64u;
    inline constexpr ULONG kSystemBootEnvironmentInformation = 90u;
    inline constexpr ULONG kSystemHypervisorInformation = 91u;
    inline constexpr ULONG kSystemCodeIntegrityInformation = 103u;
    inline constexpr ULONG kSystemKernelVaShadowInformation = 196u;
    inline constexpr ULONG kSystemSpeculationControlInformation = 201u;
    inline constexpr ULONG kCodeIntegrityOptionTestSign = 0x00000002u;
    inline constexpr ULONG kProcessDebugPort = 7u;
    inline constexpr ULONG kProcessDebugObjectHandle = 30u;
    inline constexpr ULONG kProcessDebugFlags = 31u;

    struct IxSystemKernelDebuggerInformation
    {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    };

    struct IxSystemCodeIntegrityInformation
    {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    };

    struct IxSystemHandleTableEntryInfo
    {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    };

    struct IxSystemHandleInformation
    {
        ULONG NumberOfHandles;
        IxSystemHandleTableEntryInfo Handles[1];
    };

    struct IxSystemHandleTableEntryInfoEx
    {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };

    struct IxSystemHandleInformationEx
    {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        IxSystemHandleTableEntryInfoEx Handles[1];
    };

    static bool IsCurrentProcessHandle(HANDLE processHandle) noexcept;
    static bool TryReadPointerArgument(PVOID *value, std::uint64_t &outValue) noexcept;
    static bool TryReadSizeArgument(PSIZE_T value, std::uint64_t &outValue) noexcept;

    static EncodedProc<NtCreateThread_t> g_NtCreateThreadStub;
    static EncodedProc<NtCreateThreadEx_t> g_NtCreateThreadExStub;
    static EncodedProc<NtWriteVirtualMemory_t> g_NtWriteVirtualMemoryStub;
    static EncodedProc<NtAllocateVirtualMemory_t> g_NtAllocateVirtualMemoryStub;
    static EncodedProc<NtProtectVirtualMemory_t> g_NtProtectVirtualMemoryStub;
    static EncodedProc<NtReadVirtualMemory_t> g_NtReadVirtualMemoryStub;
    static EncodedProc<NtQueryVirtualMemory_t> g_NtQueryVirtualMemoryStub;
    static EncodedProc<NtQuerySystemInformation_t> g_NtQuerySystemInformationStub;
    static EncodedProc<NtCreateSection_t> g_NtCreateSectionStub;
    static EncodedProc<NtTerminateProcess_t> g_NtTerminateProcessStub;
    static EncodedProc<NtOpenProcessToken_t> g_NtOpenProcessTokenStub;
    static EncodedProc<NtOpenThreadToken_t> g_NtOpenThreadTokenStub;
    static EncodedProc<NtOpenFile_t> g_NtOpenFileStub;
    static EncodedProc<NtQueryInformationProcess_t> g_NtQueryInformationProcessStub;
    static EncodedProc<NtQueryInformationThread_t> g_NtQueryInformationThreadStub;
    static EncodedProc<NtSetContextThread_t> g_NtSetContextThreadStub;
    static EncodedProc<NtQuerySection_t> g_NtQuerySectionStub;
    static EncodedProc<NtQueryBootOptions_t> g_NtQueryBootOptionsStub;
    static EncodedProc<NtOpenProcess_t> g_NtOpenProcessStub;
    static EncodedProc<NtOpenThread_t> g_NtOpenThreadStub;
    static EncodedProc<NtDuplicateObject_t> g_NtDuplicateObjectStub;
    static EncodedProc<NtGetContextThread_t> g_NtGetContextThreadStub;
    static EncodedProc<NtSuspendThread_t> g_NtSuspendThreadStub;
    static EncodedProc<NtResumeThread_t> g_NtResumeThreadStub;
    static EncodedProc<NtQueueApcThread_t> g_NtQueueApcThreadStub;
    static EncodedProc<NtAllocateVirtualMemoryEx_t> g_NtAllocateVirtualMemoryExStub;
    static EncodedProc<NtMapViewOfSection_t> g_NtMapViewOfSectionStub;
    static EncodedProc<NtMapViewOfSectionEx_t> g_NtMapViewOfSectionExStub;
    static EncodedProc<NtUnmapViewOfSection_t> g_NtUnmapViewOfSectionStub;
    static EncodedProc<NtUnmapViewOfSectionEx_t> g_NtUnmapViewOfSectionExStub;
    static EncodedProc<NtQueueApcThreadEx_t> g_NtQueueApcThreadExStub;
    static EncodedProc<NtQueueApcThreadEx2_t> g_NtQueueApcThreadEx2Stub;
    static EncodedProc<NtOpenProcessTokenEx_t> g_NtOpenProcessTokenExStub;
    static EncodedProc<NtOpenThreadTokenEx_t> g_NtOpenThreadTokenExStub;
    static EncodedProc<NtQuerySystemInformationEx_t> g_NtQuerySystemInformationExStub;

    using NtGetNextThread_t = NTSTATUS(NTAPI *)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                                ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);
    static EncodedProc<NtGetNextThread_t> g_NtGetNextThreadStub;

    // Minimal THREAD_BASIC_INFORMATION — only fields needed to extract the TID.
    struct IxThreadBasicInformation
    {
        NTSTATUS ExitStatus;
        ULONG Pad;
        PVOID TebBaseAddress;
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
        ULONG_PTR AffinityMask;
        LONG Priority;
        LONG BasePriority;
    };

    static DWORD GetProcessPid(HANDLE processHandle) noexcept
    {
        if (IsCurrentProcessHandle(processHandle))
        {
            return GetCurrentProcessId();
        }

        return (processHandle != NULL) ? GetProcessId(processHandle) : 0;
    }

    static bool TryReadThreadIdentity(HANDLE threadHandle, DWORD &processId, DWORD &threadId) noexcept
    {
        processId = 0;
        threadId = 0;
        if (!g_NtQueryInformationThreadStub || threadHandle == NULL)
        {
            return false;
        }

        IxThreadBasicInformation info{};
        ULONG retLen = 0;
        NTSTATUS st = g_NtQueryInformationThreadStub(threadHandle, 0, &info, static_cast<ULONG>(sizeof(info)), &retLen);
        if (!NT_SUCCESS(st))
        {
            return false;
        }

        processId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info.UniqueProcess));
        threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info.UniqueThread));
        return (processId != 0 || threadId != 0);
    }

    struct NtTargetHook
    {
        const char *Name;
        NtOperation Operation;
        IX_RUNTIME_INTERNAL::IxIhrToken TargetToken;
        IX_RUNTIME_INTERNAL::IxIhrToken SyscallStubToken;
        std::uint32_t SyscallIndex;
        std::uint8_t OriginalBytes[16];
        bool Installed;
        std::uint32_t HookMethod = SKUGGA_IPC_HOOK_METHOD_INLINE;
    };

    static NtHookCallback g_ActiveNtCallback = nullptr;

    struct ModuleRange
    {
        std::uintptr_t Base;
        std::uintptr_t End;
    };

    static bool TryResolveModuleImageRange(HMODULE module, ModuleRange &range) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0)
        {
            return false;
        }

        range.Base = reinterpret_cast<std::uintptr_t>(module);
        range.End = range.Base + nt->OptionalHeader.SizeOfImage;
        return true;
    }

    static bool HasExportDirectory(HMODULE module) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return false;
        }

        const auto &entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        return entry.VirtualAddress != 0 && entry.Size >= sizeof(IMAGE_EXPORT_DIRECTORY);
    }
    static bool AddressWithinRange(void *address, const ModuleRange &range) noexcept
    {
        std::uintptr_t value = reinterpret_cast<std::uintptr_t>(address);
        return value >= range.Base && value < range.End;
    }

    static void *ResolveNtHookToken(IX_RUNTIME_INTERNAL::IxIhrToken token, IX_RUNTIME_INTERNAL::IxIhrType type) noexcept
    {
        IX_RUNTIME_INTERNAL::IxIhrResolved resolved{};
        if (!IX_RUNTIME_INTERNAL::ResolveIndirectHandle(token, type, resolved))
        {
            return nullptr;
        }
        return resolved.Pointer;
    }

    static void *ResolveNtHookTarget(const NtTargetHook &hook) noexcept
    {
        return ResolveNtHookToken(hook.TargetToken, IX_RUNTIME_INTERNAL::IxIhrType::NtHookTarget);
    }

    static void *ResolveNtHookStub(const NtTargetHook &hook) noexcept
    {
        return ResolveNtHookToken(hook.SyscallStubToken, IX_RUNTIME_INTERNAL::IxIhrType::NtSyscallStub);
    }

    static IX_RUNTIME_INTERNAL::IxIhrToken RegisterNtHookPointer(void *pointer, IX_RUNTIME_INTERNAL::IxIhrType type,
                                                                 const char *tag, std::uint32_t flags = 0) noexcept
    {
        return IX_RUNTIME_INTERNAL::RegisterIndirectHandle(pointer, 16u, type, flags, tag);
    }

    static bool TryDecodeAbsoluteTarget(void *entry, void *&target) noexcept
    {
        target = nullptr;
        if (entry == nullptr)
        {
            return false;
        }

        auto *bytes = static_cast<std::uint8_t *>(entry);
        __try
        {
            if (bytes[0] == 0xE9)
            {
                std::int32_t rel = *reinterpret_cast<std::int32_t *>(&bytes[1]);
                target = bytes + 5 + rel;
                return true;
            }

            if (bytes[0] == 0xFF && bytes[1] == 0x25)
            {
#if defined(_WIN64)
                std::int32_t disp = *reinterpret_cast<std::int32_t *>(&bytes[2]);
                auto **slot = reinterpret_cast<void **>(bytes + 6 + disp);
#else
                auto **slot = *reinterpret_cast<void ***>(&bytes[2]);
#endif
                target = *slot;
                return true;
            }

            if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
            {
                target = *reinterpret_cast<void **>(&bytes[2]);
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            target = nullptr;
            return false;
        }

        return false;
    }

    static NtTargetHook g_NtHooks[] = {
        {"NtCreateThread", NtOperation::NtCreateThread, 0, 0, 0u, {}, false},
        {"NtCreateThreadEx", NtOperation::NtCreateThreadEx, 0, 0, 0u, {}, false},
        {"NtWriteVirtualMemory", NtOperation::NtWriteVirtualMemory, 0, 0, 0u, {}, false},
        {"NtAllocateVirtualMemory", NtOperation::NtAllocateVirtualMemory, 0, 0, 0u, {}, false},
        {"NtProtectVirtualMemory", NtOperation::NtProtectVirtualMemory, 0, 0, 0u, {}, false},
        {"NtReadVirtualMemory", NtOperation::NtReadVirtualMemory, 0, 0, 0u, {}, false},
        {"NtQueryVirtualMemory", NtOperation::NtQueryVirtualMemory, 0, 0, 0u, {}, false},
        {"NtQuerySystemInformation", NtOperation::NtQuerySystemInformation, 0, 0, 0u, {}, false},
        {"NtCreateSection", NtOperation::NtCreateSection, 0, 0, 0u, {}, false},
        {"NtTerminateProcess", NtOperation::NtTerminateProcess, 0, 0, 0u, {}, false},
        {"NtOpenProcessToken", NtOperation::NtOpenProcessToken, 0, 0, 0u, {}, false},
        {"NtOpenThreadToken", NtOperation::NtOpenThreadToken, 0, 0, 0u, {}, false},
        {"NtOpenFile", NtOperation::NtOpenFile, 0, 0, 0u, {}, false},
        {"NtQueryInformationProcess", NtOperation::NtQueryInformationProcess, 0, 0, 0u, {}, false},
        {"NtQueryInformationThread", NtOperation::NtQueryInformationThread, 0, 0, 0u, {}, false},
        {"NtSetContextThread", NtOperation::NtSetContextThread, 0, 0, 0u, {}, false},
        {"NtQuerySection", NtOperation::NtQuerySection, 0, 0, 0u, {}, false},
        {"NtQueryBootOptions", NtOperation::NtQueryBootOptions, 0, 0, 0u, {}, false},
        {"NtOpenProcess", NtOperation::NtOpenProcess, 0, 0, 0u, {}, false},
        {"NtOpenThread", NtOperation::NtOpenThread, 0, 0, 0u, {}, false},
        {"NtDuplicateObject", NtOperation::NtDuplicateObject, 0, 0, 0u, {}, false},
        {"NtGetContextThread", NtOperation::NtGetContextThread, 0, 0, 0u, {}, false},
        {"NtSuspendThread", NtOperation::NtSuspendThread, 0, 0, 0u, {}, false},
        {"NtResumeThread", NtOperation::NtResumeThread, 0, 0, 0u, {}, false},
        {"NtQueueApcThread", NtOperation::NtQueueApcThread, 0, 0, 0u, {}, false},
        {"NtAllocateVirtualMemoryEx", NtOperation::NtAllocateVirtualMemoryEx, 0, 0, 0u, {}, false},
        {"NtMapViewOfSection", NtOperation::NtMapViewOfSection, 0, 0, 0u, {}, false},
        {"NtMapViewOfSectionEx", NtOperation::NtMapViewOfSectionEx, 0, 0, 0u, {}, false},
        {"NtUnmapViewOfSection", NtOperation::NtUnmapViewOfSection, 0, 0, 0u, {}, false},
        {"NtUnmapViewOfSectionEx", NtOperation::NtUnmapViewOfSectionEx, 0, 0, 0u, {}, false},
        {"NtQueueApcThreadEx", NtOperation::NtQueueApcThreadEx, 0, 0, 0u, {}, false},
        {"NtQueueApcThreadEx2", NtOperation::NtQueueApcThreadEx2, 0, 0, 0u, {}, false},
        {"NtOpenProcessTokenEx", NtOperation::NtOpenProcessTokenEx, 0, 0, 0u, {}, false},
        {"NtOpenThreadTokenEx", NtOperation::NtOpenThreadTokenEx, 0, 0, 0u, {}, false},
        {"NtQuerySystemInformationEx", NtOperation::NtQuerySystemInformationEx, 0, 0, 0u, {}, false},
        {"NtGetNextThread", NtOperation::NtGetNextThread, 0, 0, 0u, {}, false},
    };

    static std::uint32_t HookWalkSeed() noexcept
    {
        LARGE_INTEGER counter{};
        (void)QueryPerformanceCounter(&counter);
        std::uint64_t value = static_cast<std::uint64_t>(counter.QuadPart);
        value ^= __rdtsc();
        value ^= static_cast<std::uint64_t>(GetCurrentProcessId()) << 17;
        value ^= static_cast<std::uint64_t>(GetCurrentThreadId()) << 3;
        value ^= reinterpret_cast<std::uintptr_t>(&value);
        value ^= value >> 32;
        std::uint32_t seed = static_cast<std::uint32_t>(value);
        return seed != 0 ? seed : 0x71C0FFEEu;
    }

    static std::uint32_t NextHookWalkValue(std::uint32_t &state) noexcept
    {
        state = (state * 1664525u) + 1013904223u;
        return state;
    }

    static void BuildHookWalkOrder(std::uint8_t *order, std::size_t count) noexcept
    {
        if (order == nullptr || count == 0)
        {
            return;
        }

        for (std::size_t i = 0; i < count; ++i)
        {
            order[i] = static_cast<std::uint8_t>(i);
        }

        std::uint32_t state = HookWalkSeed();
        for (std::size_t i = count - 1; i > 0; --i)
        {
            std::size_t j = NextHookWalkValue(state) % (i + 1);
            std::uint8_t tmp = order[i];
            order[i] = order[j];
            order[j] = tmp;
        }
    }

    static bool ExtractSyscallIndex(void *targetAddress, std::uint32_t &outIndex) noexcept
    {
        auto *bytes = static_cast<std::uint8_t *>(targetAddress);

#if defined(_WIN64)
        if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1 || bytes[3] != 0xB8)
            return false;
        outIndex = *reinterpret_cast<std::uint32_t *>(&bytes[4]);
#else
        if (bytes[0] != 0xB8)
            return false;
        outIndex = *reinterpret_cast<std::uint32_t *>(&bytes[1]);
#endif
        return true;
    }

    static void *BuildSyscallStub(void *targetAddress, std::uint32_t syscallIndex) noexcept
    {
#if defined(_WIN64)
        UNREFERENCED_PARAMETER(targetAddress);
        constexpr std::size_t StubSize = 16;
#else
        constexpr std::size_t StubSize = 32;
#endif
#if defined(_CONTROL_FLOW_GUARD) && (_CONTROL_FLOW_GUARD == 1)
        constexpr bool kNtStubCallerUsesCfg = true;
#else
        constexpr bool kNtStubCallerUsesCfg = false;
#endif
        IxDbgLog("BuildSyscallStub: begin index=%lu", static_cast<unsigned long>(syscallIndex));
        const auto cfgPolicy = IX_RUNTIME_INTERNAL::QueryCurrentProcessControlFlowPolicy();
        const bool cfgRegistrationRequired = cfgPolicy.CfgEnabled && kNtStubCallerUsesCfg;
        const DWORD allocProtect =
            cfgRegistrationRequired ? (PAGE_EXECUTE_READWRITE | PAGE_TARGETS_INVALID) : PAGE_READWRITE;

        void *memory = VirtualAlloc(nullptr, StubSize, MEM_COMMIT | MEM_RESERVE, allocProtect);

        if (!memory)
        {
            IxDbgLog("BuildSyscallStub: VirtualAlloc failed protect=0x%08lX gle=%lu",
                     static_cast<unsigned long>(allocProtect), static_cast<unsigned long>(GetLastError()));
            return nullptr;
        }
        IxDbgLog("BuildSyscallStub: allocated memory=%p protect=0x%08lX cfgRequired=%u", memory,
                 static_cast<unsigned long>(allocProtect), cfgRegistrationRequired ? 1u : 0u);

        auto *code = static_cast<std::uint8_t *>(memory);
#if defined(_WIN64)
        code[0] = 0x4C;
        code[1] = 0x8B;
        code[2] = 0xD1;
        code[3] = 0xB8;
        *reinterpret_cast<std::uint32_t *>(&code[4]) = syscallIndex;
        code[8] = 0x0F;
        code[9] = 0x05;
        code[10] = 0xC3;
        for (std::size_t i = 11; i < StubSize; ++i)
            code[i] = 0xCC;
#else
        auto *source = static_cast<const std::uint8_t *>(targetAddress);
        std::size_t sourceBytes = 0;
        __try
        {
            // WoW64 stubs start with MOV EAX, service-id and terminate with
            // RET/RET imm16. Preserve the actual transition sequence so this
            // remains compatible with the Windows build in the child.
            for (std::size_t i = 5; i < StubSize; ++i)
            {
                if (source[i] == 0xC3)
                {
                    sourceBytes = i + 1;
                    break;
                }
                if (source[i] == 0xC2 && i + 2 < StubSize)
                {
                    sourceBytes = i + 3;
                    break;
                }
            }
            if (sourceBytes == 0)
            {
                VirtualFree(memory, 0, MEM_RELEASE);
                return nullptr;
            }
            std::memcpy(code, source, sourceBytes);

            // Some WoW64 builds use a relative call immediately after the
            // service id. Relocate that one PC-relative operand.
            if (sourceBytes >= 10 && code[5] == 0xE8)
            {
                const std::int32_t oldDisplacement = *reinterpret_cast<const std::int32_t *>(&source[6]);
                const std::uintptr_t callTarget = reinterpret_cast<std::uintptr_t>(source + 10) + oldDisplacement;
                const std::intptr_t newDisplacement =
                    static_cast<std::intptr_t>(callTarget) - reinterpret_cast<std::intptr_t>(code + 10);
                *reinterpret_cast<std::int32_t *>(&code[6]) = static_cast<std::int32_t>(newDisplacement);
            }
            std::memset(code + sourceBytes, 0xCC, StubSize - sourceBytes);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(memory, 0, MEM_RELEASE);
            return nullptr;
        }
#endif

        DWORD oldProtect = 0;
        const DWORD finalProtect =
            cfgRegistrationRequired ? (PAGE_EXECUTE_READ | PAGE_TARGETS_NO_UPDATE) : PAGE_EXECUTE_READ;
        if (!VirtualProtect(memory, StubSize, finalProtect, &oldProtect))
        {
            IxDbgLog("BuildSyscallStub: VirtualProtect failed memory=%p protect=0x%08lX gle=%lu", memory,
                     static_cast<unsigned long>(finalProtect), static_cast<unsigned long>(GetLastError()));
            VirtualFree(memory, 0, MEM_RELEASE);
            return nullptr;
        }

        FlushInstructionCache(GetCurrentProcess(), memory, StubSize);
        IxDbgLog("BuildSyscallStub: protected memory=%p protect=0x%08lX oldProtect=0x%08lX", memory,
                 static_cast<unsigned long>(finalProtect), static_cast<unsigned long>(oldProtect));
        if (cfgRegistrationRequired && !IX_RUNTIME_INTERNAL::RegisterControlFlowGuardCallTarget(
                                           memory, IX_RUNTIME_INTERNAL::IxCfgCallTargetMode::CfgOnly, "rt.nt.stub"))
        {
            IxDbgLog("BuildSyscallStub: CFG registration failed memory=%p", memory);
            VirtualFree(memory, 0, MEM_RELEASE);
            return nullptr;
        }
        IxDbgLog("BuildSyscallStub: ready memory=%p", memory);

        return memory;
    }

    static bool TryResolveModuleSectionRange(HMODULE module, const char *sectionName, ModuleRange &range) noexcept
    {
        auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module);
        if (module == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const std::uint8_t *>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        auto *section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            char name[9]{};
            std::memcpy(name, section->Name, std::min<std::size_t>(sizeof(section->Name), 8));
            if (std::strcmp(name, sectionName) != 0)
            {
                continue;
            }

            std::size_t size = std::max<std::size_t>(section->Misc.VirtualSize, section->SizeOfRawData);
            if (size == 0)
            {
                return false;
            }

            range.Base = reinterpret_cast<std::uintptr_t>(module) + section->VirtualAddress;
            range.End = range.Base + size;
            return true;
        }

        return false;
    }

    static bool TryResolveModuleTextRange(HMODULE module, ModuleRange &range) noexcept
    {
        return TryResolveModuleSectionRange(module, ".text", range);
    }

    // ntdll's .mrdata, resolved at install. Empty on systems without the section.
    static ModuleRange g_NtdllMrdata{};

    // The loader flips ntdll's .mrdata writable while it holds the inverted function
    // table lock (RtlInsertInvertedFunctionTable -> LdrProtectMrdata). Stack walking
    // takes that lock, so these calls must not capture a trace. Uses only the
    // pseudo-handle check: GetProcessId would issue another, possibly hooked, syscall.
    static bool IsLoaderMrdataProtect(HANDLE processHandle, PVOID *baseAddress) noexcept
    {
        if (g_NtdllMrdata.Base == 0 || processHandle != reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)))
        {
            return false;
        }

        std::uint64_t base = 0;
        return TryReadPointerArgument(baseAddress, base) &&
               AddressWithinRange(reinterpret_cast<void *>(static_cast<std::uintptr_t>(base)), g_NtdllMrdata);
    }

    static bool IsCurrentProcessHandle(HANDLE processHandle) noexcept
    {
        if (processHandle == nullptr || processHandle == reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)) ||
            processHandle == GetCurrentProcess())
        {
            return true;
        }

        DWORD pid = GetProcessId(processHandle);
        return pid != 0 && pid == GetCurrentProcessId();
    }

    struct SyscallSequenceMatch
    {
        bool Found = false;
        std::size_t Offset = 0;
        std::uint32_t SyscallNumber = 0xFFFFFFFFu;
    };

    static std::uint32_t ReadUnalignedU32(const std::uint8_t *value) noexcept
    {
        std::uint32_t out = 0;
        if (value != nullptr)
        {
            std::memcpy(&out, value, sizeof(out));
        }
        return out;
    }

    static SyscallSequenceMatch FindSyscallSequence(const std::uint8_t *bytes, std::size_t size) noexcept
    {
        SyscallSequenceMatch match{};
        if (bytes == nullptr || size < 2)
        {
            return match;
        }

        for (std::size_t i = 0; i + 1 < size; ++i)
        {
            if (i + 9 < size && bytes[i] == 0x4C && bytes[i + 1] == 0x8B && bytes[i + 2] == 0xD1 &&
                bytes[i + 3] == 0xB8 && bytes[i + 8] == 0x0F && bytes[i + 9] == 0x05)
            {
                match.Found = true;
                match.Offset = i;
                match.SyscallNumber = ReadUnalignedU32(bytes + i + 4);
                return match;
            }

            if (bytes[i] == 0x0F && bytes[i + 1] == 0x05)
            {
                match.Found = true;
                match.Offset = i;
                std::size_t searchStart = i > 16 ? i - 16 : 0;
                for (std::size_t j = searchStart; j + 5 <= i; ++j)
                {
                    if (bytes[j] == 0xB8)
                    {
                        match.Offset = j;
                        match.SyscallNumber = ReadUnalignedU32(bytes + j + 1);
                        break;
                    }
                }
                return match;
            }
        }

        return match;
    }

    // Set by IxSetNtHook. Hook paths must not use function-local statics with runtime
    // initializers: MSVC's thread-safe init guard reads implicit TLS on every call,
    // and hooks run on threads whose TLS vector the loader has not allocated yet.
    static SIZE_T g_NtPageSize = 0;

    static SIZE_T NtRuntimePageSize() noexcept
    {
        return g_NtPageSize != 0 ? g_NtPageSize : 0x1000u;
    }

    static std::uintptr_t NtAlignDown(std::uintptr_t value, SIZE_T alignment) noexcept
    {
        return value & ~(static_cast<std::uintptr_t>(alignment) - 1u);
    }

    static std::uintptr_t NtAlignUp(std::uintptr_t value, SIZE_T alignment) noexcept
    {
        return NtAlignDown(value + static_cast<std::uintptr_t>(alignment) - 1u, alignment);
    }

    static bool IsReadableCommittedPage(const MEMORY_BASIC_INFORMATION &mbi) noexcept
    {
        ULONG baseProtect = mbi.Protect & 0xFFu;
        return mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && (mbi.Protect & PAGE_GUARD) == 0 &&
               baseProtect != 0 && baseProtect != PAGE_NOACCESS;
    }

    static SIZE_T QueryInstrumentationRegion(void *address, MEMORY_BASIC_INFORMATION &mbi) noexcept
    {
        IX_INTERNAL_SCOPE();
        return VirtualQuery(address, &mbi, sizeof(mbi));
    }

    static void TryObserveDirectSyscallRange(HANDLE processHandle, void *baseAddress, SIZE_T regionSize, void *caller,
                                             const char *sourceApi, NtHookContext *ctx) noexcept
    {
        if (::IxIsInternalCall() || !IsCurrentProcessHandle(processHandle) || baseAddress == nullptr || regionSize == 0)
        {
            return;
        }

        SIZE_T pageSize = NtRuntimePageSize();
        const auto address = reinterpret_cast<std::uintptr_t>(baseAddress);
        if (regionSize > UINTPTR_MAX - address || address + regionSize > UINTPTR_MAX - (pageSize - 1))
        {
            return;
        }
        std::uintptr_t start = NtAlignDown(reinterpret_cast<std::uintptr_t>(baseAddress), pageSize);
        std::uintptr_t end = NtAlignUp(
            reinterpret_cast<std::uintptr_t>(baseAddress) + static_cast<std::uintptr_t>(regionSize), pageSize);
        if (end <= start)
        {
            return;
        }

        constexpr SIZE_T kMaxScanBytes = 64 * 1024;
        // Bound address coverage as well as work; skipping inaccessible regions
        // must never turn this into an unbounded address-space walk.
        end = start + std::min<std::uintptr_t>(end - start, kMaxScanBytes);
        SIZE_T scanned = 0;
        for (std::uintptr_t page = start; page < end && scanned < kMaxScanBytes; page += pageSize)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T queried = QueryInstrumentationRegion(reinterpret_cast<void *>(page), mbi);
            if (queried == 0 || !IsReadableCommittedPage(mbi))
            {
                const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                if (queried != 0 && mbi.RegionSize <= UINTPTR_MAX - regionBase)
                {
                    const auto next = std::min<std::uintptr_t>(end, regionBase + mbi.RegionSize);
                    if (next > page && next - page >= pageSize)
                        page = next - pageSize;
                }
                scanned += pageSize;
                continue;
            }

            std::uint8_t sample[512]{};
            std::size_t readable = std::min<std::size_t>(sizeof(sample), pageSize);
            std::uintptr_t regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd > page)
            {
                readable = std::min<std::size_t>(readable, static_cast<std::size_t>(regionEnd - page));
            }

            __try
            {
                std::memcpy(sample, reinterpret_cast<const void *>(page), readable);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                scanned += pageSize;
                continue;
            }

            SyscallSequenceMatch match = FindSyscallSequence(sample, readable);
            if (!match.Found)
            {
                scanned += pageSize;
                continue;
            }

            void *stub = reinterpret_cast<void *>(page + match.Offset);
            if (ctx != nullptr)
            {
                if (ctx->Operation == NtOperation::NtProtectVirtualMemory)
                {
                    ctx->Args[5] = 1;
                    ctx->Args[6] = reinterpret_cast<std::uint64_t>(stub);
                }
                if (ctx->DataSize == 0)
                {
                    std::size_t copy = std::min<std::size_t>(sizeof(ctx->DataSample), readable);
                    std::memcpy(ctx->DataSample, sample, copy);
                    ctx->DataSize = static_cast<std::uint32_t>(copy);
                }
            }

            (void)IX_RUNTIME_INTERNAL::RegisterDirectSyscallPage(reinterpret_cast<void *>(page), pageSize, stub,
                                                                 match.SyscallNumber, caller, sample,
                                                                 static_cast<std::uint32_t>(readable), sourceApi);
            return;
        }
    }

    static void TryAnnotateProtectTarget(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize,
                                         NtHookContext &ctx) noexcept
    {
        std::uint64_t baseValue = 0;
        std::uint64_t sizeValue = 0;
        if (baseAddress == nullptr || regionSize == nullptr)
        {
            return;
        }

        __try
        {
            baseValue = reinterpret_cast<std::uint64_t>(*baseAddress);
            sizeValue = static_cast<std::uint64_t>(*regionSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            baseValue = 0;
            sizeValue = 0;
        }

        if (baseValue == 0 || sizeValue == 0)
        {
            return;
        }

        TryObserveDirectSyscallRange(processHandle, reinterpret_cast<void *>(baseValue), static_cast<SIZE_T>(sizeValue),
                                     ctx.Caller, ctx.FunctionName, &ctx);
    }

    static inline bool EvaluateNtPolicyPreCall(const char *functionName, void *caller,
                                               IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision &policy,
                                               NTSTATUS &status) noexcept
    {
        status = STATUS_SUCCESS;
        if (::IxIsInternalCall())
        {
            return false;
        }
        if (!IX_RUNTIME_INTERNAL::EvaluateNtHookPolicy(functionName, caller, policy) || policy.Ignored)
        {
            return false;
        }

        if (policy.Action == SKUGGA_IPC_HOOK_ACTION_DENY || policy.Action == SKUGGA_IPC_HOOK_ACTION_SILENT_DENY)
        {
            status = policy.Status;
            return true;
        }
        return false;
    }

    static inline void CaptureNtRegisterSnapshot(NtRegisterSnapshot &snapshot, void *caller,
                                                 const std::uint64_t args[8], NTSTATUS status) noexcept
    {
        CONTEXT context{};
        RtlCaptureContext(&context);

        snapshot.Valid = 1;
        snapshot.Rip = reinterpret_cast<std::uint64_t>(caller);
#if defined(_WIN64)
        snapshot.Rsp = context.Rsp;
        snapshot.Rbp = context.Rbp;
        snapshot.Rax = static_cast<std::uint64_t>(static_cast<std::uint32_t>(status));
        snapshot.Rbx = context.Rbx;
        snapshot.Rcx = args != nullptr ? args[0] : context.Rcx;
        snapshot.Rdx = args != nullptr ? args[1] : context.Rdx;
        snapshot.Rsi = context.Rsi;
        snapshot.Rdi = context.Rdi;
        snapshot.R8 = args != nullptr ? args[2] : context.R8;
        snapshot.R9 = args != nullptr ? args[3] : context.R9;
        snapshot.R10 = context.R10;
        snapshot.R11 = context.R11;
        snapshot.R12 = context.R12;
        snapshot.R13 = context.R13;
        snapshot.R14 = context.R14;
        snapshot.R15 = context.R15;
#else
        snapshot.Rsp = context.Esp;
        snapshot.Rbp = context.Ebp;
        snapshot.Rax = static_cast<std::uint64_t>(static_cast<std::uint32_t>(status));
        snapshot.Rbx = context.Ebx;
        snapshot.Rcx = args != nullptr ? args[0] : context.Ecx;
        snapshot.Rdx = args != nullptr ? args[1] : context.Edx;
        snapshot.Rsi = context.Esi;
        snapshot.Rdi = context.Edi;
        snapshot.R8 = args != nullptr ? args[2] : 0;
        snapshot.R9 = args != nullptr ? args[3] : 0;
        snapshot.R10 = 0;
        snapshot.R11 = 0;
        snapshot.R12 = 0;
        snapshot.R13 = 0;
        snapshot.R14 = 0;
        snapshot.R15 = 0;
#endif
        snapshot.EFlags = context.EFlags;
    }

    static inline void PublishNtEvent(NtHookContext &ctx, NTSTATUS status,
                                      const IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision &policy,
                                      bool successfulOnly) noexcept
    {
        if (!g_ActiveNtCallback || IxIsInternalCall())
        {
            return;
        }

        if (policy.Matched)
        {
            if (policy.Ignored || (!policy.Log && policy.Action == SKUGGA_IPC_HOOK_ACTION_NONE))
            {
                return;
            }
        }
        else if (successfulOnly && status != STATUS_SUCCESS)
        {
            return;
        }

        ctx.Status = status;
        ctx.PolicyAction = policy.Matched && !policy.Ignored ? policy.Action : SKUGGA_IPC_HOOK_ACTION_NONE;
        ctx.PolicyFlags = 0;
        if (policy.Matched && !policy.Ignored)
        {
            if (policy.Log)
            {
                ctx.PolicyFlags |= SKUGGA_IPC_HOOK_RULE_FLAG_LOG;
            }
            if (policy.StackTrace)
            {
                ctx.PolicyFlags |= SKUGGA_IPC_HOOK_RULE_FLAG_STACK_TRACE;
            }
            if (policy.Registers)
            {
                ctx.PolicyFlags |= SKUGGA_IPC_HOOK_RULE_FLAG_REGISTERS;
                CaptureNtRegisterSnapshot(ctx.Registers, ctx.Caller, ctx.Args, status);
                ctx.HasRegisters = ctx.Registers.Valid != 0;
            }
            if (policy.StackFabricate)
            {
                ctx.PolicyFlags |= SKUGGA_IPC_HOOK_RULE_FLAG_STACK_FABRICATE;
            }
        }

        IxEnterInternalCall();
        __try
        {
            if (policy.Trace.Count != 0)
            {
                ctx.Stack = policy.Trace;
            }
            else if (!policy.Matched || policy.StackTrace)
            {
                (void)IC_STACKTRACE::Capture(ctx.Stack, 1);
            }
            g_ActiveNtCallback(ctx);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        IxLeaveInternalCall();
    }

    static inline void PublishNtEventIfSuccessful(NtHookContext &ctx, NTSTATUS status,
                                                  const IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision &policy =
                                                      IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision{}) noexcept
    {
        PublishNtEvent(ctx, status, policy, true);
    }

    static inline void PublishNtEventAlways(NtHookContext &ctx, NTSTATUS status,
                                            const IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision &policy =
                                                IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision{}) noexcept
    {
        PublishNtEvent(ctx, status, policy, false);
    }

    static bool TryReadPointerArgument(PVOID *value, std::uint64_t &outValue) noexcept
    {
        outValue = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            outValue = reinterpret_cast<std::uint64_t>(*value);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            outValue = 0;
            return false;
        }
    }

    static bool TryReadSizeArgument(PSIZE_T value, std::uint64_t &outValue) noexcept
    {
        outValue = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            outValue = static_cast<std::uint64_t>(*value);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            outValue = 0;
            return false;
        }
    }

    static bool TryReadUlongArgument(PULONG value, std::uint64_t &outValue) noexcept
    {
        outValue = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            outValue = static_cast<std::uint64_t>(*value);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            outValue = 0;
            return false;
        }
    }

    static bool TryReadClientIdArgument(PCLIENT_ID value, std::uint64_t &processId, std::uint64_t &threadId) noexcept
    {
        processId = 0;
        threadId = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            processId = static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(value->UniqueProcess));
            threadId = static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(value->UniqueThread));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            processId = 0;
            threadId = 0;
            return false;
        }
    }

    static bool TryReadContextArgument(PCONTEXT value, std::uint64_t &instructionPointer, std::uint64_t &stackPointer,
                                       std::uint64_t &contextFlags) noexcept
    {
        instructionPointer = 0;
        stackPointer = 0;
        contextFlags = 0;
        if (value == nullptr)
        {
            return false;
        }

        __try
        {
            contextFlags = static_cast<std::uint64_t>(value->ContextFlags);
#if defined(_WIN64)
            instructionPointer = static_cast<std::uint64_t>(value->Rip);
            stackPointer = static_cast<std::uint64_t>(value->Rsp);
#else
            instructionPointer = static_cast<std::uint64_t>(value->Eip);
            stackPointer = static_cast<std::uint64_t>(value->Esp);
#endif
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            instructionPointer = 0;
            stackPointer = 0;
            contextFlags = 0;
            return false;
        }
    }

    static void TryCopyBufferSample(const void *buffer, std::size_t bufferSize, NtHookContext &ctx) noexcept
    {
        ctx.DataSize = 0;
        if (buffer == nullptr || bufferSize == 0)
        {
            return;
        }

        std::size_t sampleBytes = std::min<std::size_t>(sizeof(ctx.DataSample), bufferSize);
        __try
        {
            std::memcpy(ctx.DataSample, buffer, sampleBytes);
            ctx.DataSize = static_cast<std::uint32_t>(sampleBytes);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ctx.DataSize = 0;
        }
    }

    NTSTATUS NTAPI NtCreateThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                       POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId,
                                       PCONTEXT ThreadContext, PIX_INITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
    {
        if (!g_NtCreateThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtCreateThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtCreateThreadStub(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
                                          ThreadContext, InitialTeb, CreateSuspended);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtCreateThread;
            ctx.FunctionName = "NtCreateThread";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ClientId);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ThreadContext);
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            ctx.Args[7] = static_cast<std::uint64_t>(CreateSuspended);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtCreateThreadEx_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                         POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
                                         PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
                                         SIZE_T MaximumStackSize, PVOID AttributeList)
    {
        if (!g_NtCreateThreadExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtCreateThreadEx", caller, policy, status);
        if (!skipOriginal)
        {
            status =
                g_NtCreateThreadExStub(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine,
                                       Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtCreateThreadEx;
            ctx.FunctionName = "NtCreateThreadEx";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(StartRoutine);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(Argument);
            ctx.Args[5] = static_cast<std::uint64_t>(CreateFlags);
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            ctx.Args[7] = static_cast<std::uint64_t>(MaximumStackSize);
            (void)TryReadPointerArgument(reinterpret_cast<PVOID *>(ThreadHandle), ctx.Args[7]);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtWriteVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize,
                                             PSIZE_T NumberOfBytesWritten)
    {
        if (!g_NtWriteVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtWriteVirtualMemory", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtWriteVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtWriteVirtualMemory;
            ctx.FunctionName = "NtWriteVirtualMemory";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(Buffer);
            ctx.Args[3] = static_cast<std::uint64_t>(BufferSize);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(NumberOfBytesWritten);
            ctx.Args[5] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            TryCopyBufferSample(Buffer, BufferSize, ctx);
            if (NT_SUCCESS(status))
            {
                SIZE_T observedSize = BufferSize;
                if (NumberOfBytesWritten != nullptr)
                {
                    __try
                    {
                        observedSize = *NumberOfBytesWritten;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        observedSize = BufferSize;
                    }
                }
                ctx.Args[6] = static_cast<std::uint64_t>(observedSize);
                TryObserveDirectSyscallRange(ProcessHandle, BaseAddress, observedSize, caller, ctx.FunctionName, &ctx);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtAllocateVirtualMemory_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                                PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        if (!g_NtAllocateVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtAllocateVirtualMemory", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtAllocateVirtualMemoryStub(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType,
                                                   Protect);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtAllocateVirtualMemory;
            ctx.FunctionName = "NtAllocateVirtualMemory";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(ZeroBits);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(RegionSize);
            ctx.Args[4] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[5] = static_cast<std::uint64_t>(Protect);
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[1]);
            (void)TryReadSizeArgument(RegionSize, ctx.Args[3]);
            if (NT_SUCCESS(status) && ctx.Args[1] != 0 && ctx.Args[3] != 0)
            {
                TryObserveDirectSyscallRange(ProcessHandle, reinterpret_cast<void *>(ctx.Args[1]),
                                             static_cast<SIZE_T>(ctx.Args[3]), caller, ctx.FunctionName, &ctx);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtProtectVirtualMemory_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                               ULONG NewProtect, PULONG OldProtect)
    {
        if (!g_NtProtectVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IC_STACKTRACE::SuppressCaptureScope noStackWalk(IsLoaderMrdataProtect(ProcessHandle, BaseAddress));
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtProtectVirtualMemory", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtProtectVirtualMemoryStub(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }
        if (::IxIsInternalCall())
        {
            return status;
        }
        if (policy.Matched && !policy.Log && policy.Action == SKUGGA_IPC_HOOK_ACTION_NONE)
        {
            return status;
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtProtectVirtualMemory;
            ctx.FunctionName = "NtProtectVirtualMemory";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(RegionSize);
            ctx.Args[3] = static_cast<std::uint64_t>(NewProtect);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(OldProtect);
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[1]);
            (void)TryReadSizeArgument(RegionSize, ctx.Args[2]);
            (void)TryReadUlongArgument(OldProtect, ctx.Args[4]);
            TryAnnotateProtectTarget(ProcessHandle, BaseAddress, RegionSize, ctx);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtReadVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize,
                                            PSIZE_T NumberOfBytesRead)
    {
        if (!g_NtReadVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtReadVirtualMemory", caller, policy, status);
        DWORD targetPid = 0;
        if (ProcessHandle == nullptr || ProcessHandle == reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)))
        {
            targetPid = GetCurrentProcessId();
        }
        else
        {
            targetPid = GetProcessId(ProcessHandle);
        }
        if (!skipOriginal)
        {
            status = g_NtReadVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        }
        SIZE_T bytesRead = 0;
        if (NT_SUCCESS(status))
        {
            if (NumberOfBytesRead != nullptr)
            {
                __try
                {
                    bytesRead = *NumberOfBytesRead;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    bytesRead = BufferSize;
                }
            }
            else
            {
                bytesRead = BufferSize;
            }
        }

        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtReadVirtualMemory;
            ctx.FunctionName = "NtReadVirtualMemory";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(Buffer);
            ctx.Args[3] = static_cast<std::uint64_t>(BufferSize);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(NumberOfBytesRead);
            ctx.Args[5] = static_cast<std::uint64_t>(bytesRead);
            ctx.Args[7] = static_cast<std::uint64_t>(targetPid);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueryVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
                                             PVOID MemoryInformation, SIZE_T MemoryInformationLength,
                                             PSIZE_T ReturnLength)
    {
        if (!g_NtQueryVirtualMemoryStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQueryVirtualMemory", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQueryVirtualMemoryStub(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation,
                                                MemoryInformationLength, ReturnLength);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryVirtualMemory;
            ctx.FunctionName = "NtQueryVirtualMemory";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(MemoryInformationClass);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(MemoryInformation);
            ctx.Args[4] = static_cast<std::uint64_t>(MemoryInformationLength);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ReturnLength);
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQuerySystemInformation_Hook(ULONG SystemInformationClass, PVOID SystemInformation,
                                                 ULONG SystemInformationLength, PULONG ReturnLength)
    {
        if (!g_NtQuerySystemInformationStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQuerySystemInformation", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQuerySystemInformationStub(SystemInformationClass, SystemInformation, SystemInformationLength,
                                                    ReturnLength);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQuerySystemInformation;
            ctx.FunctionName = "NtQuerySystemInformation";
            ctx.Caller = caller;
            ctx.Args[0] = static_cast<std::uint64_t>(SystemInformationClass);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(SystemInformation);
            ctx.Args[2] = static_cast<std::uint64_t>(SystemInformationLength);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ReturnLength);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQuerySystemInformationEx_Hook(ULONG SystemInformationClass, PVOID InputBuffer,
                                                   ULONG InputBufferLength, PVOID SystemInformation,
                                                   ULONG SystemInformationLength, PULONG ReturnLength)
    {
        if (!g_NtQuerySystemInformationExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQuerySystemInformationEx", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQuerySystemInformationExStub(SystemInformationClass, InputBuffer, InputBufferLength,
                                                      SystemInformation, SystemInformationLength, ReturnLength);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQuerySystemInformationEx;
            ctx.FunctionName = "NtQuerySystemInformationEx";
            ctx.Caller = caller;
            ctx.Args[0] = static_cast<std::uint64_t>(SystemInformationClass);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(InputBuffer);
            ctx.Args[2] = static_cast<std::uint64_t>(InputBufferLength);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(SystemInformation);
            ctx.Args[4] = static_cast<std::uint64_t>(SystemInformationLength);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ReturnLength);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtGetNextThread_Hook(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                        ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle)
    {
        if (!g_NtGetNextThreadStub || !NewThreadHandle)
            return STATUS_NOT_IMPLEMENTED;

        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtGetNextThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtGetNextThreadStub(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags,
                                           NewThreadHandle);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtGetNextThread;
            ctx.FunctionName = "NtGetNextThread";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[2] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(NewThreadHandle);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtCreateSection_Hook(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                                        ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
    {
        if (!g_NtCreateSectionStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtCreateSection", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtCreateSectionStub(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
                                           SectionPageProtection, AllocationAttributes, FileHandle);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtCreateSection;
            ctx.FunctionName = "NtCreateSection";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(MaximumSize);
            ctx.Args[4] = static_cast<std::uint64_t>(SectionPageProtection);
            ctx.Args[5] = static_cast<std::uint64_t>(AllocationAttributes);
            ctx.Args[6] = reinterpret_cast<std::uint64_t>(FileHandle);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtTerminateProcess_Hook(HANDLE ProcessHandle, NTSTATUS ExitStatus)
    {
        if (!g_NtTerminateProcessStub)
            return STATUS_NOT_IMPLEMENTED;

        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtTerminateProcess", caller, policy, status);
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtTerminateProcess;
            ctx.FunctionName = "NtTerminateProcess";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(ExitStatus);
            ctx.Args[6] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            ctx.Args[7] = kNtHookTerminateBreakpointMarker;

            PublishNtEventAlways(ctx, status, policy);
            IX_RUNTIME_INTERNAL::FlushHookEvents();
            (void)SKUGGA_IPC::DrainPendingHookEventsSynchronously(64);
        }

        if (skipOriginal)
        {
            return status;
        }
        return g_NtTerminateProcessStub(ProcessHandle, ExitStatus);
    }

    NTSTATUS NTAPI NtOpenProcessToken_Hook(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle)
    {
        if (!g_NtOpenProcessTokenStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtOpenProcessToken", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtOpenProcessTokenStub(ProcessHandle, DesiredAccess, TokenHandle);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenProcessToken;
            ctx.FunctionName = "NtOpenProcessToken";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(TokenHandle);

            PublishNtEventAlways(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtOpenThreadToken_Hook(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                          PHANDLE TokenHandle)
    {
        if (!g_NtOpenThreadTokenStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtOpenThreadToken", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtOpenThreadTokenStub(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenThreadToken;
            ctx.FunctionName = "NtOpenThreadToken";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = static_cast<std::uint64_t>(OpenAsSelf);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(TokenHandle);

            PublishNtEventAlways(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtOpenFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                   PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
    {
        if (!g_NtOpenFileStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtOpenFile", caller, policy, status);
        if (!skipOriginal)
        {
            status =
                g_NtOpenFileStub(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenFile;
            ctx.FunctionName = "NtOpenFile";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(FileHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(IoStatusBlock);
            ctx.Args[4] = static_cast<std::uint64_t>(ShareAccess);
            ctx.Args[5] = static_cast<std::uint64_t>(OpenOptions);

            PublishNtEventAlways(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueryInformationProcess_Hook(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                  PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                  PULONG ReturnLength)
    {
        if (!g_NtQueryInformationProcessStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQueryInformationProcess", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQueryInformationProcessStub(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                                     ProcessInformationLength, ReturnLength);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryInformationProcess;
            ctx.FunctionName = "NtQueryInformationProcess";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(ProcessInformationClass);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ProcessInformation);
            ctx.Args[3] = static_cast<std::uint64_t>(ProcessInformationLength);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ReturnLength);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueryInformationThread_Hook(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                 PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                 PULONG ReturnLength)
    {
        if (!g_NtQueryInformationThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQueryInformationThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQueryInformationThreadStub(ThreadHandle, ThreadInformationClass, ThreadInformation,
                                                    ThreadInformationLength, ReturnLength);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryInformationThread;
            ctx.FunctionName = "NtQueryInformationThread";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(ThreadInformationClass);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ThreadInformation);
            ctx.Args[3] = static_cast<std::uint64_t>(ThreadInformationLength);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ReturnLength);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtSetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        if (!g_NtSetContextThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtSetContextThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtSetContextThreadStub(ThreadHandle, ThreadContext);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtSetContextThread;
            ctx.FunctionName = "NtSetContextThread";
            ctx.Caller = caller;
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadContext);
            (void)TryReadContextArgument(ThreadContext, ctx.Args[2], ctx.Args[3], ctx.Args[4]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[5] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[6] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQuerySection_Hook(HANDLE SectionHandle, ULONG SectionInformationClass, PVOID InformationBuffer,
                                       ULONG InformationBufferSize, PULONG ResultLength)
    {
        if (!g_NtQuerySectionStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQuerySection", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQuerySectionStub(SectionHandle, SectionInformationClass, InformationBuffer,
                                          InformationBufferSize, ResultLength);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQuerySection;
            ctx.FunctionName = "NtQuerySection";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(SectionInformationClass);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(InformationBuffer);
            ctx.Args[3] = static_cast<std::uint64_t>(InformationBufferSize);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ResultLength);

            PublishNtEventAlways(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueryBootOptions_Hook(PVOID BootOptions, PULONG BootOptionsLength)
    {
        if (!g_NtQueryBootOptionsStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQueryBootOptions", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQueryBootOptionsStub(BootOptions, BootOptionsLength);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueryBootOptions;
            ctx.FunctionName = "NtQueryBootOptions";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(BootOptions);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BootOptionsLength);

            PublishNtEventAlways(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtOpenProcess_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
    {
        if (!g_NtOpenProcessStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtOpenProcess", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtOpenProcessStub(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            std::uint64_t targetProcessId = 0;
            std::uint64_t targetThreadId = 0;
            (void)TryReadClientIdArgument(ClientId, targetProcessId, targetThreadId);
            ctx.Operation = NtOperation::NtOpenProcess;
            ctx.FunctionName = "NtOpenProcess";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = targetProcessId;
            ctx.Args[3] = targetThreadId;
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            (void)TryReadPointerArgument(reinterpret_cast<PVOID *>(ProcessHandle), ctx.Args[5]);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtOpenThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                     POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
    {
        if (!g_NtOpenThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtOpenThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtOpenThreadStub(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            std::uint64_t targetProcessId = 0;
            std::uint64_t targetThreadId = 0;
            (void)TryReadClientIdArgument(ClientId, targetProcessId, targetThreadId);
            ctx.Operation = NtOperation::NtOpenThread;
            ctx.FunctionName = "NtOpenThread";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = targetProcessId;
            ctx.Args[3] = targetThreadId;
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ObjectAttributes);
            (void)TryReadPointerArgument(reinterpret_cast<PVOID *>(ThreadHandle), ctx.Args[5]);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtDuplicateObject_Hook(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
                                          PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes,
                                          ULONG Options)
    {
        if (!g_NtDuplicateObjectStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtDuplicateObject", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtDuplicateObjectStub(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle,
                                             DesiredAccess, Attributes, Options);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtDuplicateObject;
            ctx.FunctionName = "NtDuplicateObject";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SourceProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(SourceHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(TargetProcessHandle);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(TargetHandle);
            ctx.Args[4] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[5] = static_cast<std::uint64_t>(Attributes);
            ctx.Args[6] = static_cast<std::uint64_t>(Options);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT ThreadContext)
    {
        if (!g_NtGetContextThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtGetContextThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtGetContextThreadStub(ThreadHandle, ThreadContext);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtGetContextThread;
            ctx.FunctionName = "NtGetContextThread";
            ctx.Caller = caller;
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ThreadContext);
            (void)TryReadContextArgument(ThreadContext, ctx.Args[2], ctx.Args[3], ctx.Args[4]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[5] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[6] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtSuspendThread_Hook(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        if (!g_NtSuspendThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtSuspendThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtSuspendThreadStub(ThreadHandle, PreviousSuspendCount);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Operation = NtOperation::NtSuspendThread;
            ctx.FunctionName = "NtSuspendThread";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(PreviousSuspendCount);
            (void)TryReadUlongArgument(PreviousSuspendCount, ctx.Args[2]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[3] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[4] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }

        return status;
    }

    NTSTATUS NTAPI NtResumeThread_Hook(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        if (!g_NtResumeThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtResumeThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtResumeThreadStub(ThreadHandle, PreviousSuspendCount);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Operation = NtOperation::NtResumeThread;
            ctx.FunctionName = "NtResumeThread";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(PreviousSuspendCount);
            (void)TryReadUlongArgument(PreviousSuspendCount, ctx.Args[2]);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[3] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[4] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }

        return status;
    }

    NTSTATUS NTAPI NtQueueApcThread_Hook(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2,
                                         PVOID ApcArgument3)
    {
        if (!g_NtQueueApcThreadStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQueueApcThread", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQueueApcThreadStub(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThread;
            ctx.FunctionName = "NtQueueApcThread";
            ctx.Caller = caller;
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument3);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[5] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[6] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtAllocateVirtualMemoryEx_Hook(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                  ULONG AllocationType, ULONG PageProtection, PVOID ExtendedParameters,
                                                  ULONG ExtendedParameterCount)
    {
        if (!g_NtAllocateVirtualMemoryExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtAllocateVirtualMemoryEx", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtAllocateVirtualMemoryExStub(ProcessHandle, BaseAddress, RegionSize, AllocationType,
                                                     PageProtection, ExtendedParameters, ExtendedParameterCount);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtAllocateVirtualMemoryEx;
            ctx.FunctionName = "NtAllocateVirtualMemoryEx";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(RegionSize);
            ctx.Args[3] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[4] = static_cast<std::uint64_t>(PageProtection);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ExtendedParameters);
            ctx.Args[6] = static_cast<std::uint64_t>(ExtendedParameterCount);
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[1]);
            (void)TryReadSizeArgument(RegionSize, ctx.Args[2]);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtMapViewOfSectionEx_Hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                             PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
                                             ULONG Win32Protect, PVOID ExtendedParameters, ULONG ExtendedParameterCount)
    {
        if (!g_NtMapViewOfSectionExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtMapViewOfSectionEx", caller, policy, status);
        if (!skipOriginal)
        {
            status =
                g_NtMapViewOfSectionExStub(SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize,
                                           AllocationType, Win32Protect, ExtendedParameters, ExtendedParameterCount);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtMapViewOfSectionEx;
            ctx.FunctionName = "NtMapViewOfSectionEx";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(SectionOffset);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ViewSize);
            ctx.Args[5] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[6] = static_cast<std::uint64_t>(Win32Protect);
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[2]);
            (void)TryReadSizeArgument(ViewSize, ctx.Args[4]);
            if (NT_SUCCESS(status) && ctx.Args[2] != 0 && ctx.Args[4] != 0)
            {
                TryObserveDirectSyscallRange(ProcessHandle, reinterpret_cast<void *>(ctx.Args[2]),
                                             static_cast<SIZE_T>(ctx.Args[4]), caller, ctx.FunctionName, &ctx);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtMapViewOfSection_Hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
                                           ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
                                           PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
                                           ULONG Win32Protect)
    {
        if (!g_NtMapViewOfSectionStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtMapViewOfSection", caller, policy, status);
        if (!skipOriginal)
        {
            status =
                g_NtMapViewOfSectionStub(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset,
                                         ViewSize, InheritDisposition, AllocationType, Win32Protect);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtMapViewOfSection;
            ctx.FunctionName = "NtMapViewOfSection";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(SectionHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ViewSize);
            ctx.Args[4] = static_cast<std::uint64_t>(InheritDisposition);
            ctx.Args[5] = static_cast<std::uint64_t>(AllocationType);
            ctx.Args[6] = static_cast<std::uint64_t>(Win32Protect);
            ctx.Args[7] = static_cast<std::uint64_t>(GetProcessPid(ProcessHandle));
            (void)TryReadPointerArgument(BaseAddress, ctx.Args[2]);
            (void)TryReadSizeArgument(ViewSize, ctx.Args[3]);
            if (NT_SUCCESS(status) && ctx.Args[2] != 0 && ctx.Args[3] != 0)
            {
                TryObserveDirectSyscallRange(ProcessHandle, reinterpret_cast<void *>(ctx.Args[2]),
                                             static_cast<SIZE_T>(ctx.Args[3]), caller, ctx.FunctionName, &ctx);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtUnmapViewOfSection_Hook(HANDLE ProcessHandle, PVOID BaseAddress)
    {
        if (!g_NtUnmapViewOfSectionStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtUnmapViewOfSection", caller, policy, status);
        DWORD targetPid = GetProcessPid(ProcessHandle);
        if (!skipOriginal)
        {
            status = g_NtUnmapViewOfSectionStub(ProcessHandle, BaseAddress);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtUnmapViewOfSection;
            ctx.FunctionName = "NtUnmapViewOfSection";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(targetPid);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtUnmapViewOfSectionEx_Hook(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags)
    {
        if (!g_NtUnmapViewOfSectionExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtUnmapViewOfSectionEx", caller, policy, status);
        DWORD targetPid = GetProcessPid(ProcessHandle);
        if (!skipOriginal)
        {
            status = g_NtUnmapViewOfSectionExStub(ProcessHandle, BaseAddress, Flags);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtUnmapViewOfSectionEx;
            ctx.FunctionName = "NtUnmapViewOfSectionEx";
            ctx.Caller = caller;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(BaseAddress);
            ctx.Args[2] = static_cast<std::uint64_t>(targetPid);
            ctx.Args[3] = static_cast<std::uint64_t>(Flags);
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueueApcThreadEx_Hook(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PVOID ApcRoutine,
                                           PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3)
    {
        if (!g_NtQueueApcThreadExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQueueApcThreadEx", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQueueApcThreadExStub(ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1,
                                              ApcArgument2, ApcArgument3);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThreadEx;
            ctx.FunctionName = "NtQueueApcThreadEx";
            ctx.Caller = caller;
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(UserApcReserveHandle);
            ctx.Args[2] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ApcArgument3);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[6] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[7] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtQueueApcThreadEx2_Hook(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, ULONG QueueUserApcFlags,
                                            PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2,
                                            PVOID ApcArgument3)
    {
        if (!g_NtQueueApcThreadEx2Stub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtQueueApcThreadEx2", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtQueueApcThreadEx2Stub(ThreadHandle, UserApcReserveHandle, QueueUserApcFlags, ApcRoutine,
                                               ApcArgument1, ApcArgument2, ApcArgument3);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtQueueApcThreadEx2;
            ctx.FunctionName = "NtQueueApcThreadEx2";
            ctx.Caller = caller;
            DWORD targetPid = 0;
            DWORD targetTid = 0;
            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = reinterpret_cast<std::uint64_t>(UserApcReserveHandle);
            ctx.Args[2] = static_cast<std::uint64_t>(QueueUserApcFlags);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(ApcRoutine);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(ApcArgument1);
            ctx.Args[5] = reinterpret_cast<std::uint64_t>(ApcArgument2);
            if (TryReadThreadIdentity(ThreadHandle, targetPid, targetTid))
            {
                ctx.Args[6] = static_cast<std::uint64_t>(targetTid);
                ctx.Args[7] = static_cast<std::uint64_t>(targetPid);
            }
            PublishNtEventIfSuccessful(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtOpenProcessTokenEx_Hook(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
                                             PHANDLE TokenHandle)
    {
        if (!g_NtOpenProcessTokenExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtOpenProcessTokenEx", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtOpenProcessTokenExStub(ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenProcessTokenEx;
            ctx.FunctionName = "NtOpenProcessTokenEx";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ProcessHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = static_cast<std::uint64_t>(HandleAttributes);
            ctx.Args[3] = reinterpret_cast<std::uint64_t>(TokenHandle);

            PublishNtEventAlways(ctx, status, policy);
        }
        return status;
    }

    NTSTATUS NTAPI NtOpenThreadTokenEx_Hook(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                                            ULONG HandleAttributes, PHANDLE TokenHandle)
    {
        if (!g_NtOpenThreadTokenExStub)
            return STATUS_NOT_IMPLEMENTED;
        void *caller = _ReturnAddress();
        IX_RUNTIME_INTERNAL::IxNtHookPolicyDecision policy{};
        NTSTATUS status = STATUS_SUCCESS;
        bool skipOriginal = EvaluateNtPolicyPreCall("NtOpenThreadTokenEx", caller, policy, status);
        if (!skipOriginal)
        {
            status = g_NtOpenThreadTokenExStub(ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle);
        }
        if (g_ActiveNtCallback)
        {
            NtHookContext ctx{};
            ctx.Operation = NtOperation::NtOpenThreadTokenEx;
            ctx.FunctionName = "NtOpenThreadTokenEx";
            ctx.Caller = caller;

            ctx.Args[0] = reinterpret_cast<std::uint64_t>(ThreadHandle);
            ctx.Args[1] = static_cast<std::uint64_t>(DesiredAccess);
            ctx.Args[2] = static_cast<std::uint64_t>(OpenAsSelf);
            ctx.Args[3] = static_cast<std::uint64_t>(HandleAttributes);
            ctx.Args[4] = reinterpret_cast<std::uint64_t>(TokenHandle);

            PublishNtEventAlways(ctx, status, policy);
        }
        return status;
    }

    static void *GetHookEntry(const char *name) noexcept
    {
        if (std::strcmp(name, "NtCreateThread") == 0)
            return reinterpret_cast<void *>(&NtCreateThread_Hook);
        if (std::strcmp(name, "NtCreateThreadEx") == 0)
            return reinterpret_cast<void *>(&NtCreateThreadEx_Hook);
        if (std::strcmp(name, "NtWriteVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtWriteVirtualMemory_Hook);
        if (std::strcmp(name, "NtAllocateVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtAllocateVirtualMemory_Hook);
        if (std::strcmp(name, "NtProtectVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtProtectVirtualMemory_Hook);
        if (std::strcmp(name, "NtReadVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtReadVirtualMemory_Hook);
        if (std::strcmp(name, "NtQueryVirtualMemory") == 0)
            return reinterpret_cast<void *>(&NtQueryVirtualMemory_Hook);
        if (std::strcmp(name, "NtQuerySystemInformation") == 0)
            return reinterpret_cast<void *>(&NtQuerySystemInformation_Hook);
        if (std::strcmp(name, "NtCreateSection") == 0)
            return reinterpret_cast<void *>(&NtCreateSection_Hook);
        if (std::strcmp(name, "NtTerminateProcess") == 0)
            return reinterpret_cast<void *>(&NtTerminateProcess_Hook);
        if (std::strcmp(name, "NtOpenProcessToken") == 0)
            return reinterpret_cast<void *>(&NtOpenProcessToken_Hook);
        if (std::strcmp(name, "NtOpenThreadToken") == 0)
            return reinterpret_cast<void *>(&NtOpenThreadToken_Hook);
        if (std::strcmp(name, "NtOpenFile") == 0)
            return reinterpret_cast<void *>(&NtOpenFile_Hook);
        if (std::strcmp(name, "NtQueryInformationProcess") == 0)
            return reinterpret_cast<void *>(&NtQueryInformationProcess_Hook);
        if (std::strcmp(name, "NtQueryInformationThread") == 0)
            return reinterpret_cast<void *>(&NtQueryInformationThread_Hook);
        if (std::strcmp(name, "NtSetContextThread") == 0)
            return reinterpret_cast<void *>(&NtSetContextThread_Hook);
        if (std::strcmp(name, "NtQuerySection") == 0)
            return reinterpret_cast<void *>(&NtQuerySection_Hook);
        if (std::strcmp(name, "NtQueryBootOptions") == 0)
            return reinterpret_cast<void *>(&NtQueryBootOptions_Hook);
        if (std::strcmp(name, "NtOpenProcess") == 0)
            return reinterpret_cast<void *>(&NtOpenProcess_Hook);
        if (std::strcmp(name, "NtOpenThread") == 0)
            return reinterpret_cast<void *>(&NtOpenThread_Hook);
        if (std::strcmp(name, "NtDuplicateObject") == 0)
            return reinterpret_cast<void *>(&NtDuplicateObject_Hook);
        if (std::strcmp(name, "NtGetContextThread") == 0)
            return reinterpret_cast<void *>(&NtGetContextThread_Hook);
        if (std::strcmp(name, "NtSuspendThread") == 0)
            return reinterpret_cast<void *>(&NtSuspendThread_Hook);
        if (std::strcmp(name, "NtResumeThread") == 0)
            return reinterpret_cast<void *>(&NtResumeThread_Hook);
        if (std::strcmp(name, "NtQueueApcThread") == 0)
            return reinterpret_cast<void *>(&NtQueueApcThread_Hook);
        if (std::strcmp(name, "NtAllocateVirtualMemoryEx") == 0)
            return reinterpret_cast<void *>(&NtAllocateVirtualMemoryEx_Hook);
        if (std::strcmp(name, "NtMapViewOfSection") == 0)
            return reinterpret_cast<void *>(&NtMapViewOfSection_Hook);
        if (std::strcmp(name, "NtMapViewOfSectionEx") == 0)
            return reinterpret_cast<void *>(&NtMapViewOfSectionEx_Hook);
        if (std::strcmp(name, "NtUnmapViewOfSection") == 0)
            return reinterpret_cast<void *>(&NtUnmapViewOfSection_Hook);
        if (std::strcmp(name, "NtUnmapViewOfSectionEx") == 0)
            return reinterpret_cast<void *>(&NtUnmapViewOfSectionEx_Hook);
        if (std::strcmp(name, "NtQueueApcThreadEx") == 0)
            return reinterpret_cast<void *>(&NtQueueApcThreadEx_Hook);
        if (std::strcmp(name, "NtQueueApcThreadEx2") == 0)
            return reinterpret_cast<void *>(&NtQueueApcThreadEx2_Hook);
        if (std::strcmp(name, "NtOpenProcessTokenEx") == 0)
            return reinterpret_cast<void *>(&NtOpenProcessTokenEx_Hook);
        if (std::strcmp(name, "NtOpenThreadTokenEx") == 0)
            return reinterpret_cast<void *>(&NtOpenThreadTokenEx_Hook);
        if (std::strcmp(name, "NtQuerySystemInformationEx") == 0)
            return reinterpret_cast<void *>(&NtQuerySystemInformationEx_Hook);
        if (std::strcmp(name, "NtGetNextThread") == 0)
            return reinterpret_cast<void *>(&NtGetNextThread_Hook);
        return nullptr;
    }
} // namespace IX_NT

bool IxSetNtHook(NtHookCallback callback) noexcept
{
    using namespace IX_NT;

    if (!callback)
        return false;

    g_ActiveNtCallback = callback;
    ResetNtHookInitFault();
    IxDbgLog("IxSetNtHook: begin");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        SetNtHookInitFault(NtHookInitFaultCode::NtdllMissing, "ntdll.dll", nullptr);
        IxDbgLog("IxSetNtHook: ntdll missing");
        return false;
    }

    ModuleRange ntdllImage{};
    if (!TryResolveModuleImageRange(ntdll, ntdllImage))
    {
        SetNtHookInitFault(NtHookInitFaultCode::ExportOutsideImage, "ntdll.dll", ntdll);
        IxDbgLog("IxSetNtHook: ntdll image range failed base=%p", ntdll);
        return false;
    }

    ModuleRange ntdllText{};
    if (!TryResolveModuleTextRange(ntdll, ntdllText))
    {
        SetNtHookInitFault(NtHookInitFaultCode::NtdllTextMissing, "ntdll.dll", ntdll);
        IxDbgLog("IxSetNtHook: ntdll text range failed base=%p", ntdll);
        return false;
    }

    if (!TryResolveModuleSectionRange(ntdll, ".mrdata", g_NtdllMrdata))
    {
        g_NtdllMrdata = ModuleRange{};
    }
    IC_STACKTRACE::PrepareCaptureSuppression();
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    g_NtPageSize = systemInfo.dwPageSize != 0 ? systemInfo.dwPageSize : 0x1000u;

    if (!HasExportDirectory(ntdll))
    {
        SetNtHookInitFault(NtHookInitFaultCode::NtdllExportDirectoryMissing, "ntdll.dll", ntdll);
        IxDbgLog("IxSetNtHook: ntdll export directory missing base=%p", ntdll);
        return false;
    }

    const bool enableNtMemoryHooks = ShouldEnableNtMemoryHooks();
    bool anyInstalled = false;

    std::uint8_t hookOrder[RTL_NUMBER_OF(g_NtHooks)]{};
    BuildHookWalkOrder(hookOrder, RTL_NUMBER_OF(g_NtHooks));

    for (std::size_t walkIndex = 0; walkIndex < RTL_NUMBER_OF(g_NtHooks); ++walkIndex)
    {
        auto &hook = g_NtHooks[hookOrder[walkIndex]];
        IxDbgLog("IxSetNtHook: hook[%zu/%zu] name=%s installed=%u", walkIndex + 1, RTL_NUMBER_OF(g_NtHooks), hook.Name,
                 hook.Installed ? 1u : 0u);
        if (!IX_RUNTIME_INTERNAL::ShouldInstallNtHookByPolicy(hook.Name))
        {
            IxDbgLog("IxSetNtHook: skip by policy name=%s", hook.Name);
            continue;
        }
        if (!enableNtMemoryHooks && !IX_RUNTIME_INTERNAL::IsCliHookPolicyActive() && IsNtMemoryHookName(hook.Name))
        {
            IxDbgLog("IxSetNtHook: skip memory hook name=%s", hook.Name);
            continue;
        }

        if (hook.Installed)
        {
            anyInstalled = true;
            continue;
        }

        FARPROC addr = GetProcAddress(ntdll, hook.Name);
        if (!addr)
        {
            SetNtHookInitFault(NtHookInitFaultCode::ExportMissing, hook.Name, nullptr);
            IxDbgLog("IxSetNtHook: export missing name=%s", hook.Name);
            continue;
        }

        void *targetAddress = reinterpret_cast<void *>(addr);
        IxDbgLog("IxSetNtHook: target name=%s address=%p", hook.Name, targetAddress);
        if (!AddressWithinRange(targetAddress, ntdllImage))
        {
            SetNtHookInitFault(NtHookInitFaultCode::ExportOutsideImage, hook.Name, targetAddress);
            IxDbgLog("IxSetNtHook: outside image name=%s address=%p", hook.Name, targetAddress);
            continue;
        }

        if (!AddressWithinRange(targetAddress, ntdllText))
        {
            SetNtHookInitFault(NtHookInitFaultCode::ExportOutsideText, hook.Name, targetAddress);
            IxDbgLog("IxSetNtHook: outside text name=%s address=%p", hook.Name, targetAddress);
            continue;
        }

        std::uint32_t sysIndex = 0;
        if (!ExtractSyscallIndex(targetAddress, sysIndex))
        {
            void *redirectTarget = nullptr;
            if (TryDecodeAbsoluteTarget(targetAddress, redirectTarget) && redirectTarget != nullptr &&
                !AddressWithinRange(redirectTarget, ntdllImage))
            {
                SetNtHookInitFault(NtHookInitFaultCode::ExportRedirectedOutsideImage, hook.Name, targetAddress,
                                   redirectTarget);
            }
            else
            {
                SetNtHookInitFault(NtHookInitFaultCode::UnexpectedStubBytes, hook.Name, targetAddress);
            }
            IxDbgLog("IxSetNtHook: unexpected stub name=%s address=%p", hook.Name, targetAddress);
            continue;
        }

        hook.SyscallIndex = sysIndex;
        IxDbgLog("IxSetNtHook: syscall name=%s index=%lu", hook.Name, static_cast<unsigned long>(sysIndex));
        hook.TargetToken =
            RegisterNtHookPointer(targetAddress, IX_RUNTIME_INTERNAL::IxIhrType::NtHookTarget, hook.Name);
        IxDbgLog("IxSetNtHook: target token name=%s token=0x%llX", hook.Name,
                 static_cast<unsigned long long>(hook.TargetToken));
        if (hook.TargetToken == 0)
        {
            SetNtHookInitFault(NtHookInitFaultCode::PatchInstallFailed, hook.Name, targetAddress, nullptr, sysIndex);
            IxDbgLog("IxSetNtHook: target token failed name=%s address=%p", hook.Name, targetAddress);
            continue;
        }

        void *stubCode = BuildSyscallStub(targetAddress, sysIndex);
        if (!stubCode)
        {
            SetNtHookInitFault(NtHookInitFaultCode::SyscallStubAllocFailed, hook.Name, targetAddress, nullptr,
                               sysIndex);
            IxDbgLog("IxSetNtHook: syscall stub alloc/register failed name=%s", hook.Name);
            continue;
        }
        IxDbgLog("IxSetNtHook: syscall stub name=%s stub=%p", hook.Name, stubCode);

        hook.SyscallStubToken =
            RegisterNtHookPointer(stubCode, IX_RUNTIME_INTERNAL::IxIhrType::NtSyscallStub, hook.Name,
                                  IX_RUNTIME_INTERNAL::kIxIhrFlagExecutable | IX_RUNTIME_INTERNAL::kIxIhrFlagOwned);
        if (hook.SyscallStubToken == 0)
        {
            SetNtHookInitFault(NtHookInitFaultCode::SyscallStubAllocFailed, hook.Name, targetAddress, nullptr,
                               sysIndex);
            IxDbgLog("IxSetNtHook: syscall stub token failed name=%s stub=%p", hook.Name, stubCode);
            continue;
        }

        if (std::strcmp(hook.Name, "NtCreateThread") == 0)
            g_NtCreateThreadStub = reinterpret_cast<NtCreateThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtCreateThreadEx") == 0)
            g_NtCreateThreadExStub = reinterpret_cast<NtCreateThreadEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtWriteVirtualMemory") == 0)
            g_NtWriteVirtualMemoryStub = reinterpret_cast<NtWriteVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtAllocateVirtualMemory") == 0)
            g_NtAllocateVirtualMemoryStub = reinterpret_cast<NtAllocateVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtProtectVirtualMemory") == 0)
            g_NtProtectVirtualMemoryStub = reinterpret_cast<NtProtectVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtReadVirtualMemory") == 0)
            g_NtReadVirtualMemoryStub = reinterpret_cast<NtReadVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryVirtualMemory") == 0)
            g_NtQueryVirtualMemoryStub = reinterpret_cast<NtQueryVirtualMemory_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQuerySystemInformation") == 0)
            g_NtQuerySystemInformationStub = reinterpret_cast<NtQuerySystemInformation_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtCreateSection") == 0)
            g_NtCreateSectionStub = reinterpret_cast<NtCreateSection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtTerminateProcess") == 0)
            g_NtTerminateProcessStub = reinterpret_cast<NtTerminateProcess_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenProcessToken") == 0)
            g_NtOpenProcessTokenStub = reinterpret_cast<NtOpenProcessToken_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenThreadToken") == 0)
            g_NtOpenThreadTokenStub = reinterpret_cast<NtOpenThreadToken_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenFile") == 0)
            g_NtOpenFileStub = reinterpret_cast<NtOpenFile_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryInformationProcess") == 0)
            g_NtQueryInformationProcessStub = reinterpret_cast<NtQueryInformationProcess_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryInformationThread") == 0)
            g_NtQueryInformationThreadStub = reinterpret_cast<NtQueryInformationThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtSetContextThread") == 0)
            g_NtSetContextThreadStub = reinterpret_cast<NtSetContextThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQuerySection") == 0)
            g_NtQuerySectionStub = reinterpret_cast<NtQuerySection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueryBootOptions") == 0)
            g_NtQueryBootOptionsStub = reinterpret_cast<NtQueryBootOptions_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenProcess") == 0)
            g_NtOpenProcessStub = reinterpret_cast<NtOpenProcess_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenThread") == 0)
            g_NtOpenThreadStub = reinterpret_cast<NtOpenThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtDuplicateObject") == 0)
            g_NtDuplicateObjectStub = reinterpret_cast<NtDuplicateObject_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtGetContextThread") == 0)
            g_NtGetContextThreadStub = reinterpret_cast<NtGetContextThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtSuspendThread") == 0)
            g_NtSuspendThreadStub = reinterpret_cast<NtSuspendThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtResumeThread") == 0)
            g_NtResumeThreadStub = reinterpret_cast<NtResumeThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueueApcThread") == 0)
            g_NtQueueApcThreadStub = reinterpret_cast<NtQueueApcThread_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtAllocateVirtualMemoryEx") == 0)
            g_NtAllocateVirtualMemoryExStub = reinterpret_cast<NtAllocateVirtualMemoryEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtMapViewOfSection") == 0)
            g_NtMapViewOfSectionStub = reinterpret_cast<NtMapViewOfSection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtMapViewOfSectionEx") == 0)
            g_NtMapViewOfSectionExStub = reinterpret_cast<NtMapViewOfSectionEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtUnmapViewOfSection") == 0)
            g_NtUnmapViewOfSectionStub = reinterpret_cast<NtUnmapViewOfSection_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtUnmapViewOfSectionEx") == 0)
            g_NtUnmapViewOfSectionExStub = reinterpret_cast<NtUnmapViewOfSectionEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueueApcThreadEx") == 0)
            g_NtQueueApcThreadExStub = reinterpret_cast<NtQueueApcThreadEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQueueApcThreadEx2") == 0)
            g_NtQueueApcThreadEx2Stub = reinterpret_cast<NtQueueApcThreadEx2_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenProcessTokenEx") == 0)
            g_NtOpenProcessTokenExStub = reinterpret_cast<NtOpenProcessTokenEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtOpenThreadTokenEx") == 0)
            g_NtOpenThreadTokenExStub = reinterpret_cast<NtOpenThreadTokenEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtQuerySystemInformationEx") == 0)
            g_NtQuerySystemInformationExStub = reinterpret_cast<NtQuerySystemInformationEx_t>(stubCode);
        else if (std::strcmp(hook.Name, "NtGetNextThread") == 0)
            g_NtGetNextThreadStub = reinterpret_cast<NtGetNextThread_t>(stubCode);

        void *hookEntry = GetHookEntry(hook.Name);
        if (!hookEntry)
        {
            SetNtHookInitFault(NtHookInitFaultCode::HookEntryMissing, hook.Name, targetAddress, nullptr, sysIndex);
            IxDbgLog("IxSetNtHook: hook entry missing name=%s", hook.Name);
            continue;
        }
        hook.HookMethod = IX_RUNTIME_INTERNAL::HookMethodForNtHookByPolicy(hook.Name);
        IxDbgLog("IxSetNtHook: installing name=%s target=%p entry=%p method=%lu", hook.Name, targetAddress, hookEntry,
                 static_cast<unsigned long>(hook.HookMethod));

        IX_NT_METHODS::NtHookPatch patch{hook.Name, targetAddress, hookEntry, hook.OriginalBytes, hook.HookMethod};
        if (!IX_NT_METHODS::InstallNtHookPatch(patch))
        {
            SetNtHookInitFault(NtHookInitFaultCode::PatchInstallFailed, hook.Name, targetAddress, nullptr, sysIndex);
            IxDbgLog("IxSetNtHook: install failed name=%s target=%p entry=%p", hook.Name, targetAddress, hookEntry);
            continue;
        }
        hook.HookMethod = patch.Method;

        hook.Installed = true;
        anyInstalled = true;
        IxDbgLog("IxSetNtHook: installed name=%s method=%lu", hook.Name, static_cast<unsigned long>(hook.HookMethod));
    }

    IxDbgLog("IxSetNtHook: end anyInstalled=%u", anyInstalled ? 1u : 0u);
    return anyInstalled;
}

void IxRemoveNtHook() noexcept
{
    using namespace IX_NT;

    for (auto &hook : g_NtHooks)
    {
        void *targetAddress = ResolveNtHookTarget(hook);
        if (!hook.Installed || targetAddress == nullptr)
            continue;

        IX_NT_METHODS::NtHookPatch patch{hook.Name, targetAddress, GetHookEntry(hook.Name), hook.OriginalBytes,
                                         hook.HookMethod};
        IX_NT_METHODS::RemoveNtHookPatch(patch);
        IX_RUNTIME_INTERNAL::ReleaseIndirectHandle(hook.TargetToken);
        IX_RUNTIME_INTERNAL::ReleaseIndirectHandle(hook.SyscallStubToken);
        hook.TargetToken = 0;
        hook.SyscallStubToken = 0;
        hook.Installed = false;
    }

    g_ActiveNtCallback = nullptr;
}

bool IxCheckNtHookIntegrity(std::uint32_t *mismatchCount) noexcept
{
    using namespace IX_NT;

    std::uint32_t mismatches = 0;

    for (const auto &hook : g_NtHooks)
    {
        void *targetAddress = ResolveNtHookTarget(hook);
        if (!hook.Installed || targetAddress == nullptr)
        {
            continue;
        }

        void *expectedHook = GetHookEntry(hook.Name);
        if (expectedHook == nullptr)
        {
            ++mismatches;
            continue;
        }

        IX_NT_METHODS::NtHookPatch patch{hook.Name, targetAddress, expectedHook,
                                         const_cast<std::uint8_t *>(hook.OriginalBytes), hook.HookMethod};
        if (!IX_NT_METHODS::CheckNtHookPatch(patch))
        {
            ++mismatches;
        }
    }

    if (mismatchCount != nullptr)
    {
        *mismatchCount = mismatches;
    }

    return mismatches == 0;
}

bool IxGetLastNtHookInitFault(NtHookInitFault *faultOut) noexcept
{
    if (faultOut == nullptr)
    {
        return false;
    }

    *faultOut = IX_NT::g_LastNtHookInitFault;
    return faultOut->Code != NtHookInitFaultCode::None;
}

std::size_t IxCollectNtHookStubInfos(NtHookStubInfo *out, std::size_t capacity) noexcept
{
    if (out == nullptr || capacity == 0)
        return 0;

    std::size_t count = 0;
    for (const auto &hook : IX_NT::g_NtHooks)
    {
        if (count >= capacity)
            break;
        void *stubCode = IX_NT::ResolveNtHookStub(hook);
        if (stubCode == nullptr)
            continue;
        out[count].StubBase = stubCode;
        out[count].StubSize = 16u;
        out[count].HookName = hook.Name;
        ++count;
    }
    return count;
}

std::size_t IxCollectNtHookPatchInfos(NtHookPatchInfo *out, std::size_t capacity) noexcept
{
    if (out == nullptr || capacity == 0)
        return 0;

    std::size_t count = 0;
    for (const auto &hook : IX_NT::g_NtHooks)
    {
        if (count >= capacity)
            break;
        void *targetAddress = IX_NT::ResolveNtHookTarget(hook);
        if (!hook.Installed || targetAddress == nullptr)
            continue;
        out[count].PatchAddress = targetAddress;
        out[count].PatchSize = IX_NT_METHODS::NtHookPatchSize(hook.HookMethod);
        std::memcpy(out[count].OriginalBytes, hook.OriginalBytes, sizeof(hook.OriginalBytes));
        out[count].HookName = hook.Name;
        out[count].Flags = IX_NT_METHODS::NtHookPatchFlag(hook.HookMethod);
        ++count;
    }
    return count;
}
