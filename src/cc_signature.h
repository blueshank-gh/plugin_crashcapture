// cc_signature - cross-platform / cross-arch signature scan + address resolution.

/*
// declare the targets you want, resolved by symbol first, then by sig if that fails
static const CCTarget my_targets[] = {
    // resolves straight to the symbol
    {"my_func", "server", "_ZSomeSymbol", NULL, {{CC_STEP_END, 0, 0}}},
    // finds the sig, then follows the operand to the real address
    {"my_data", "vphysics", NULL, "80 3D ?? ?? ?? ?? 00", {{CC_STEP_ABS32, 2, 0}, {CC_STEP_END, 0, 0}}},
};

// this registers the table, do it once before Sig_Init.
Sig_Register(my_targets, 2);

// this resolves and caches every registered target.
Sig_Init();

// this grabs a resolved address by key, returns 0 if it couldn't resolve.
uintptr_t addr = Sig_Get("my_func");

// or skip the registry entirely and scan a module directly.
uintptr_t hit = Sig_Scan("vphysics", "48 8B ?? C3");
*/

#pragma once
#include "crashcapture.h"

namespace CrashCapture {
    // --------- cc-sig-pattern ---
    static const int kSigMaxLen = 64;

    struct CCPattern {
        unsigned char bytes[kSigMaxLen];
        unsigned char mask[kSigMaxLen]; // 1 = match, 0 = wildcard
        int len; // 0 == invalid
    };

    // parse an IDA pattern ("48 8B ?? C3")
    bool Sig_Compile(const char* ida, CCPattern* out);

    // first match in module `m`, or 0
    uintptr_t Sig_Find(const CCModule* m, const CCPattern* p);

    // up to `max` matches into `out`, returns count. Use to assert uniqueness.
    int Sig_FindAll(const CCModule* m, const CCPattern* p, uintptr_t* out, int max);

    // compile + find in the loaded module named `module`, 0 if absent/no match.
    uintptr_t Sig_Scan(const char* module, const char* ida);

    // --------- cc-sig-resolve ---
    uintptr_t Sig_RelTarget(uintptr_t at, int opOff, int insnLen); // rip-rel / rel32
    uintptr_t Sig_Abs32(uintptr_t at, int opOff); // x86 abs operand
    uintptr_t Sig_Deref(uintptr_t at); // *(void**)at

    // --------- cc-sig-registry ---
    enum CCStepOp {
        CC_STEP_END = 0,
        CC_STEP_REL, // Sig_RelTarget(cur, a, b)
        CC_STEP_ABS32, // Sig_Abs32(cur, a)
        CC_STEP_DEREF, // Sig_Deref(cur)
        CC_STEP_ADD, // cur += a
    };

    struct CCResolveStep {
        CCStepOp op;
        int a, b;
    };

    struct CCTarget {
        const char* key; // stable id
        const char* module; // basename: "server", "vphysics"
        const char* symbol; // tried first, or NULL
        const char* sig; // IDA pattern fallback, or NULL
        CCResolveStep steps[4]; // applied to the sig hit; END-terminated
    };

    // resolve one target directly (no cache), symbol first, else sig + steps.
    uintptr_t Sig_Resolve(const CCTarget* t);

    // register a target table (static lifetime; pointer retained), before Sig_Init.
    void Sig_Register(const CCTarget* targets, int count);

    // resolve all registered targets and cache by key, call once at init.
    void Sig_Init();

    // cached address for `key`, or 0, resolves on demand if not yet cached.
    uintptr_t Sig_Get(const char* key);
}
