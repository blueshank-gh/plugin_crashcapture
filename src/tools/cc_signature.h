// cc_signature - cross-platform / cross-arch signature scan + address resolution.

/*
// declare the targets you want, resolved by symbol first, then by sig if that fails
static const CCTarget my_targets[] = {
    // resolves straight to the symbol
    {"my_func", "server", "_ZSomeSymbol", NULL, {{CC_STEP_END, 0, 0}}},
    // finds the sig, then follows the operand to the real address
    {"my_data", "vphysics", NULL, "80 3D ?? ?? ?? ?? 00", {{CC_STEP_ABS32, 2, 0}, {CC_STEP_END, 0, 0}}},
};

// this registers the table, do it once before Sig::Init.
Sig::Register(my_targets, 2);

// this resolves and caches every registered target.
Sig::Init();

// this grabs a resolved address by key, returns 0 if it couldn't resolve.
uintptr_t addr = Sig::Get("my_func");

// or skip the registry entirely and scan a module directly.
uintptr_t hit = Sig::Scan("vphysics", "48 8B ?? C3");
*/

#pragma once
#include "crashcapture.h"

namespace CrashCapture {
    // --------- cc-sig-pattern ---
    static const int kSigMaxLen = 128;

    struct CCPattern {
        unsigned char bytes[kSigMaxLen];
        unsigned char mask[kSigMaxLen]; // 1 = match, 0 = wildcard
        int len; // 0 == invalid
    };

    // --------- cc-sig-registry ---
    enum CCStepOp {
        CC_STEP_END = 0,
        CC_STEP_REL, // Sig::RelTarget(cur, a, b)
        CC_STEP_ABS32, // Sig::Abs32(cur, a)
        CC_STEP_DEREF, // Sig::Deref(cur)
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

    namespace Sig {
        // --------- cc-sig-pattern ---
        bool Compile(const char* ida, CCPattern* out); // parse an IDA pattern ("48 8B ?? C3")
        uintptr_t Find(const CCModule* m, const CCPattern* p); // first match in module `m`, or 0
        int FindAll(const CCModule* m, const CCPattern* p, uintptr_t* out, int max); // up to `max` matches, returns count
        uintptr_t Scan(const char* module, const char* ida);  // compile + find in the loaded module named `module`, 0 if absent/no match

        // --------- cc-sig-resolve ---
        uintptr_t RelTarget(uintptr_t at, int opOff, int insnLen); // rip-rel / rel32
        uintptr_t Abs32(uintptr_t at, int opOff); // x86 abs operand
        uintptr_t Deref(uintptr_t at); // *(void**)at

        // --------- cc-sig-registry ---
        uintptr_t Resolve(const CCTarget* t); // resolve one target directly (no cache)
        void Register(const CCTarget* targets, int count); // register a target table (static lifetime), before Init
        void Init(); // resolve all registered targets and cache by key
        uintptr_t Get(const char* key); // cached address for `key`, or 0, resolves on demand
    }
}
