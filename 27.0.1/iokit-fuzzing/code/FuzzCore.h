// FuzzCore.h — on-device IOKit user-client instrumentation core (C API).
//
// The safety-first contract for a SANDBOX IOKit enumerator/fuzzer. Published as an
// educational artifact: note the staged modes (zero-risk default) and the crash-recovery
// / adaptive-blocklist / circuit-breaker design — a fuzzer that *can* panic a device must
// make forward progress without re-triggering the same panic, and must refuse to keep
// running into a wall. Full rationale: ../README.md and ../experiments/results.md.
#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Staged run modes — step up from zero-risk to full method fuzzing.
typedef enum {
    FUZZ_MODE_ENUMERATE = 0, // list services only; never open a user client (zero risk)
    FUZZ_MODE_OPEN      = 1, // enumerate + open/close connection types; never call a method
    FUZZ_MODE_CALL      = 2, // full: enumerate + open + IOConnectCallMethod fuzzing
    FUZZ_MODE_SIGPROBE  = 3, // per selector, sweep (scalarCnt,structSize) with zero content to
                             // discover accepted argument shapes (signatures). Low risk.
    FUZZ_MODE_CONTENT   = 4, // fuzz CONTENT within known-valid shapes from targets.tsv
                             // (reaches driver parsing logic). Higher risk — like CALL.
} fuzz_mode_t;

typedef struct {
    uint64_t iterations;         // call-phase iterations completed
    uint64_t targets_open;       // distinct services with >=1 openable type
    uint64_t errors;             // calls that returned != KERN_SUCCESS
    uint64_t last_selector;
    uint32_t last_type;
    char     last_class[128];
    uint64_t skipped_blocklist;  // selectors skipped because their signature is blocklisted
    uint64_t signatures;         // accepted argument shapes found in SIGPROBE mode
} fuzz_stats_t;

typedef void (*fuzz_progress_cb)(const fuzz_stats_t *stats, void *ctx);

typedef struct {
    const char *log_dir;         // absolute path to the app container Documents dir
    uint64_t    seed;            // 0 => derive from clock (logged either way)
    uint32_t    selector_max;    // selectors fuzzed per call are in [0, selector_max]
    uint32_t    open_type_max;   // connection types probed per service: [0, open_type_max)
    uint32_t    max_struct_in;   // upper bound on input struct size (bytes)
    uint32_t    max_scalar_in;   // upper bound on scalar input count
    uint32_t    progress_every;  // fire progress callback every N call iterations
    uint32_t    mode;            // fuzz_mode_t
    uint32_t    inter_call_delay_us; // pacing: sleep this long between method calls
    const char *only_class;      // if non-empty, only services whose class name CONTAINS
                                 // this substring are opened/fuzzed (empty/NULL = all)
} fuzz_config_t;

// Run control.
void fuzz_stop(void);
bool fuzz_is_running(void);
void fuzz_set_paused(bool paused); // thermal/battery guard, driven from the UI
bool fuzz_is_paused(void);

// Runs enumeration + fuzz loop on the CALLING thread. Blocks until fuzz_stop().
void fuzz_run(const fuzz_config_t *cfg, fuzz_progress_cb cb, void *ctx);

// Crash safety / recovery.
//
// On startup call fuzz_recover_pending(): if a pending breadcrumb was left behind
// (previous run died mid-call — most likely a kernel panic) it is moved into
// suspects.jsonl, its (class,type,selector) trigger is appended to the permanent
// blocklist so it is NEVER exercised again, and the consecutive-crash counter is
// incremented. Returns 1 if a suspect was recovered, 0 otherwise.
int  fuzz_recover_pending(const char *log_dir);

int  fuzz_consecutive_crashes(const char *log_dir); // crashes since last clean stop / reset (circuit breaker)
int  fuzz_total_crashes(const char *log_dir);       // lifetime crash-recoveries for this install
int  fuzz_blocklist_count(const char *log_dir);     // permanently-skipped crash triggers
void fuzz_reset_health(const char *log_dir);        // user action: clear the consecutive-crash breaker

#ifdef __cplusplus
}
#endif
