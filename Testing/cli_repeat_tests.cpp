#include "Telemetry/cli_events.h"
#include "Telemetry/event_formatting.h"

using namespace skugga::injector;

int main()
{
    unsigned checks = 0;
    const auto feed = [&checks](ServerContext &ctx, UINT32 count, UINT32 expected, bool printed, UINT32 tid = 1)
    {
        SKUGGA_IPC_HOOK_EVENT event{};
        event.ThreadId = tid;
        event.CallerFlags = EncodeRepeatCount(1u, count);
        const bool actual = ApplyCliRepeatAnnotation(ctx, event);
        ++checks;
        if (actual != printed || DecodeRepeatCount(event.CallerFlags) != expected ||
            (event.CallerFlags & ~IX_HOOK_CALLER_REPEAT_MASK) != 1u)
        {
            std::printf("FAIL check=%u count=%u total=%u printed=%u\n", checks, count,
                        DecodeRepeatCount(event.CallerFlags), actual);
            return false;
        }
        return true;
    };

    // Every partition of eight calls must end at x8, irrespective of when the
    // DLL worker drains its queue (including 1+7, 7+1, 4+4 and single records).
    for (unsigned partition = 0; partition < 128; ++partition)
    {
        ServerContext ctx{};
        UINT32 batch = 0;
        UINT32 total = 0;
        for (unsigned i = 0; i < 8; ++i)
        {
            ++batch;
            if (i != 7 && (partition & (1u << i)) == 0)
                continue;
            total += batch;
            const bool expectedPrint = !ctx.HasLastPrintedCliEvent || total <= 4 || total == 8 ||
                                       (ctx.LastPrintedCliRepeatMilestone < 4 && total > 4);
            if (!feed(ctx, batch, total, expectedPrint))
                return 1;
            batch = 0;
        }
        if (ctx.LastPrintedCliRepeatMilestone != 8)
            return 2;
    }

    ServerContext ctx{};
    if (!feed(ctx, 5, 5, true) || !feed(ctx, 2, 7, false) || !feed(ctx, 3, 10, true) || !feed(ctx, 5, 15, false) ||
        !feed(ctx, 20, 35, true) || !feed(ctx, 4095, 4095, true) || !feed(ctx, 1, 4095, false) ||
        !feed(ctx, 2, 2, true, 2) || !feed(ctx, 1, 1, true, 1))
        return 3;
    std::printf("[repeat-tests] passed=%u\n", checks);
    return 0;
}
