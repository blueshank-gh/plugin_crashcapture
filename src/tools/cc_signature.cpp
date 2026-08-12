// cc_signature - see cc_signature.h.

#include "tools/cc_signature.h"
#include <string.h>

#if defined(CC_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#endif

namespace CrashCapture {
    static const uintptr_t kPageMask = 0xFFF; // 4 KiB pages on all targets

    // --------- cc-sig-pattern ---
    static int HexVal(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    bool Sig::Compile(const char* ida, CCPattern* out)
    {
        if (!out) return false;
        out->len = 0;
        if (!ida) return false;

        int n = 0;
        for (const char* p = ida; *p; ) {
            if (*p == ' ' || *p == '\t') { ++p; continue; }
            if (n >= kSigMaxLen) { out->len = 0; return false; }
            if (*p == '?') {
                out->bytes[n] = 0;
                out->mask[n] = 0;
                ++n; ++p;
                if (*p == '?') ++p; // accept "??" as one wildcard
                continue;
            }
            int hi = HexVal(p[0]);
            int lo = p[1] ? HexVal(p[1]) : -1;
            if (hi < 0 || lo < 0) { out->len = 0; return false; }
            out->bytes[n] = (unsigned char)((hi << 4) | lo);
            out->mask[n] = 1;
            ++n; p += 2;
        }
        out->len = n;
        return n > 0;
    }

    static void BuildSkip(const CCPattern* p, int skip[256])
    {
        const int len = p->len;
        int lastWild = -1;
        for (int i = 0; i < len; ++i)
            if (!p->mask[i]) lastWild = i;

        int deflt = len - 1 - lastWild; // == len when there is no wildcard
        if (deflt < 1) deflt = 1;
        for (int b = 0; b < 256; ++b) skip[b] = deflt;

        for (int i = lastWild + 1; i < len - 1; ++i)
            if (p->mask[i]) skip[p->bytes[i]] = len - 1 - i;
    }

    static int ScanRange(uintptr_t base, uintptr_t end, const CCPattern* p, uintptr_t* out, int max)
    {
        if (!p || p->len <= 0 || max <= 0 || end <= base) return 0;
        const int len = p->len;
        if (end - base < (uintptr_t)len) return 0;

        int skip[256];
        BuildSkip(p, skip);

        uintptr_t readableEnd = base; // exclusive: bytes < this are confirmed mapped
        uintptr_t pos = base;
        int count = 0;

        while (pos + (uintptr_t)len <= end) {
            if (pos + (uintptr_t)len > readableEnd) {
                uintptr_t probe = readableEnd > pos ? readableEnd : pos;
                bool hole = false;
                while (readableEnd < pos + (uintptr_t)len) {
                    uintptr_t pageStart = probe & ~kPageMask;
                    if (!Mem::IsReadable((void*)pageStart, 1)) {
                        pos = pageStart + kPageMask + 1; // jump past the unmapped page
                        readableEnd = pos;
                        hole = true;
                        break;
                    }
                    readableEnd = pageStart + kPageMask + 1;
                    probe = readableEnd;
                }
                if (hole) continue;
            }

            int j = len - 1;
            while (j >= 0 && (p->mask[j] == 0 || *(const unsigned char*)(pos + j) == p->bytes[j])) --j;

            if (j < 0) {
                out[count++] = pos;
                if (count >= max) return count;
                ++pos; // seek overlapping matches
                continue;
            }
            pos += (uintptr_t)skip[*(const unsigned char*)(pos + len - 1)];
        }
        return count;
    }

    static int ScanCore(const CCModule* m, const CCPattern* p, uintptr_t* out, int max)
    {
        if (!m) return 0;
        return ScanRange(m->base, m->base + m->size, p, out, max);
    }

    uintptr_t Sig::Find(const CCModule* m, const CCPattern* p)
    {
        uintptr_t hit = 0;
        return ScanCore(m, p, &hit, 1) ? hit : 0;
    }

    int Sig::FindAll(const CCModule* m, const CCPattern* p, uintptr_t* out, int max)
    {
        return ScanCore(m, p, out, max);
    }

    uintptr_t Sig::Scan(const char* module, const char* ida)
    {
        const CCModule* m = module ? Modules::FindByName(module) : NULL;
        if (!m) return 0;
        CCPattern pat;
        if (!Sig::Compile(ida, &pat)) return 0;
        return Sig::Find(m, &pat);
    }

    // --------- cc-sig-resolve ---
    uintptr_t Sig::RelTarget(uintptr_t at, int opOff, int insnLen)
    {
        uintptr_t opnd = at + (uintptr_t)opOff;
        if (!Mem::IsReadable((void*)opnd, 4)) return 0;
        int32_t disp;
        memcpy(&disp, (void*)opnd, 4);
        return at + (uintptr_t)insnLen + (uintptr_t)(intptr_t)disp;
    }

    uintptr_t Sig::Abs32(uintptr_t at, int opOff)
    {
        uintptr_t opnd = at + (uintptr_t)opOff;
        if (!Mem::IsReadable((void*)opnd, 4)) return 0;
        uint32_t v;
        memcpy(&v, (void*)opnd, 4);
        return (uintptr_t)v;
    }

    uintptr_t Sig::Deref(uintptr_t at)
    {
        if (!Mem::IsReadable((void*)at, sizeof(void*))) return 0;
        void* p;
        memcpy(&p, (void*)at, sizeof(void*));
        return (uintptr_t)p;
    }

    // --------- cc-sig-anchor ---

    uintptr_t Sig::FindLiteral(const CCModule* m, const char* text)
    {
        if (!m || !text || !*text) return 0;
        size_t n = strlen(text);
        if (n + 1 > (size_t)kSigMaxLen) return 0;

        CCPattern pat;
        for (size_t i = 0; i <= n; ++i) {
            pat.bytes[i] = (unsigned char)text[i];
            pat.mask[i] = 1;
        }
        pat.len = (int)n + 1;

        size_t span = 0;
        uintptr_t lb = Modules::FileExtent(m, &span);
        uintptr_t hit = 0;
        return ScanRange(lb, lb + span, &pat, &hit, 1) ? hit : 0;
    }

    int Sig::FindRefs(const CCModule* m, uintptr_t target, uintptr_t* out, int max)
    {
        if (!m || !target || !out || max <= 0) return 0;

        const uintptr_t base = m->base + 1; // x64 peeks at the modrm byte behind the operand
        const uintptr_t end = m->base + m->size;
        int count = 0;
        bool pageOk = false;

        for (uintptr_t a = base; a + 4 <= end; ++a) {
            if (!pageOk || (a & kPageMask) == 0) {
                if (!Mem::IsReadable((void*)(a & ~kPageMask), 1)) { a = (a | kPageMask); pageOk = false; continue; }
                pageOk = true;
            }

            #if defined(CC_X64)
                // rip-relative: the disp32 always ends its instruction, and the modrm byte
                // right before it is mod=00 rm=101.
                if ((*(const unsigned char*)(a - 1) & 0xC7) != 0x05) continue;
            #endif

            uint32_t raw;
            memcpy(&raw, (const void*)a, 4);

            #if defined(CC_X64)
                if (a + 4 + (uintptr_t)(intptr_t)(int32_t)raw != target) continue;
            #else
                if ((uintptr_t)raw != target) continue;
            #endif

            out[count++] = a;
            if (count >= max) break;
        }
        return count;
    }

    uintptr_t Sig::FuncStart(const CCModule* m, uintptr_t inside)
    {
        if (!m || !inside) return 0;

        #if defined(CC_WINDOWS) && defined(CC_X64)
            {
                uintptr_t imageBase = 0;
                PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry((DWORD64)inside, (PDWORD64)&imageBase, NULL);
                for (int hop = 0; rf && imageBase && hop < 8; ++hop) {
                    const unsigned char* ui = (const unsigned char*)(imageBase + ((const uint32_t*)rf)[2]);
                    if (!Mem::IsReadable(ui, 4) || (ui[0] & 0x20) == 0) break;
                    const uint32_t* parent = (const uint32_t*)(ui + 4 + 2 * ((ui[2] + 1) & ~1));
                    if (!Mem::IsReadable(parent, 12)) break;
                    rf = (PRUNTIME_FUNCTION)parent;
                }
                if (rf && imageBase) return imageBase + rf->BeginAddress;
            }
        #endif

        const uintptr_t kMaxBack = 0x600;
        uintptr_t low = m->base + 2;
        if (inside > kMaxBack && inside - kMaxBack > low) low = inside - kMaxBack;

        for (uintptr_t c = inside & ~(uintptr_t)0xF; c >= low; c -= 16) {
            if (!Mem::IsReadable((void*)(c - 2), 3)) break;
            unsigned char prev = *(const unsigned char*)(c - 1);
            #if defined(CC_WINDOWS)
                if (prev == 0xCC && *(const unsigned char*)(c - 2) == 0xCC) return c;
            #else
                if (*(const unsigned char*)c == 0x55 &&
                    (prev == 0x90 || prev == 0x00 || prev == 0xCC || prev == 0xC3)) return c;
            #endif
        }
        return 0;
    }

    int Sig::AnchorAll(const char* module, const char* literal, uintptr_t* out, int max)
    {
        if (!out || max <= 0) return 0;
        const CCModule* m = module ? Modules::FindByName(module) : NULL;
        if (!m) return 0;

        uintptr_t lit = Sig::FindLiteral(m, literal);
        if (!lit) return 0;

        uintptr_t refs[8];
        int nrefs = Sig::FindRefs(m, lit, refs, 8);

        int count = 0;
        for (int i = 0; i < nrefs; ++i) {
            uintptr_t fn = Sig::FuncStart(m, refs[i]);
            if (!fn) continue;
            bool dup = false;
            for (int j = 0; j < count; ++j) if (out[j] == fn) { dup = true; break; }
            if (dup) continue;
            out[count++] = fn;
            if (count >= max) break;
        }
        return count;
    }

    uintptr_t Sig::Anchor(const char* module, const char* literal)
    {
        const CCModule* m = module ? Modules::FindByName(module) : NULL;
        if (!m) return 0;

        uintptr_t lit = Sig::FindLiteral(m, literal);
        if (!lit) return 0;

        uintptr_t refs[8];
        int nrefs = Sig::FindRefs(m, lit, refs, 8);

        uintptr_t best = 0;
        uintptr_t bestDelta = (uintptr_t)-1;
        for (int i = 0; i < nrefs; ++i) {
            uintptr_t fn = Sig::FuncStart(m, refs[i]);
            if (!fn || fn > refs[i]) continue;
            uintptr_t d = refs[i] - fn;
            if (d < bestDelta) { bestDelta = d; best = fn; }
        }
        return best;
    }

    // --------- cc-sig-registry ---
    uintptr_t Sig::Resolve(const CCTarget* t)
    {
        if (!t) return 0;

        uintptr_t cur = 0;
        if (t->symbol && t->symbol[0]) {
            cur = Sym::Lookup(t->module, t->symbol);
            if (!cur && t->module) cur = Sym::Lookup(NULL, t->symbol); // fall back to global search
        }
        if (!cur) {
            if (!t->sig || !t->sig[0]) return 0;

            const CCModule* m = t->module ? Modules::FindByName(t->module) : NULL;
            if (!m) return 0;

            CCPattern pat;
            if (!Sig::Compile(t->sig, &pat)) return 0;

            cur = Sig::Find(m, &pat);
        }
        if (!cur) return 0;

        for (int i = 0; i < 4 && t->steps[i].op != CC_STEP_END; ++i) {
            const CCResolveStep& s = t->steps[i];
            switch (s.op) {
                case CC_STEP_REL: cur = Sig::RelTarget(cur, s.a, s.b); break;
                case CC_STEP_ABS32: cur = Sig::Abs32(cur, s.a); break;
                case CC_STEP_DEREF: cur = Sig::Deref(cur); break;
                case CC_STEP_ADD: cur = cur + (uintptr_t)(intptr_t)s.a; break;
                default: return 0;
            }
            if (!cur) return 0;
        }
        return cur;
    }

    static const int kMaxTables = 8;
    static const int kMaxCache  = 64;
    static const int kSigMaxTries = 5;
    static const uint64_t kSigRetryMs = 1000; // at most one attempt per this many ms

    static const CCTarget* g_tables[kMaxTables];
    static int g_tableCount[kMaxTables];
    static int g_nTables = 0;

    struct Cached { const char* key; uintptr_t addr; uint64_t failMs; int tries; };
    static Cached g_cache[kMaxCache];
    static int g_nCache = 0;

    static const CCTarget* FindTarget(const char* key)
    {
        for (int t = 0; t < g_nTables; ++t)
            for (int i = 0; i < g_tableCount[t]; ++i) {
                const CCTarget* tg = &g_tables[t][i];
                if (tg->key && strcmp(tg->key, key) == 0) return tg;
            }
        return NULL;
    }

    static bool CacheLookup(const char* key, uintptr_t* out)
    {
        for (int i = 0; i < g_nCache; ++i)
            if (g_cache[i].key && strcmp(g_cache[i].key, key) == 0) { *out = g_cache[i].addr; return true; }
        return false;
    }

    static void CacheStore(const char* key, uintptr_t addr)
    {
        if (!addr || g_nCache >= kMaxCache) return;
        for (int i = 0; i < g_nCache; ++i)
            if (g_cache[i].key && strcmp(g_cache[i].key, key) == 0) { g_cache[i].addr = addr; return; }
        g_cache[g_nCache].key = key;
        g_cache[g_nCache].addr = addr;
        ++g_nCache;
    }

    void Sig::Register(const CCTarget* targets, int count)
    {
        if (!targets || count <= 0 || g_nTables >= kMaxTables) return;
        g_tables[g_nTables] = targets;
        g_tableCount[g_nTables] = count;
        ++g_nTables;
    }

    void Sig::Init()
    {
        for (int t = 0; t < g_nTables; ++t)
            for (int i = 0; i < g_tableCount[t]; ++i) {
                const CCTarget* tg = &g_tables[t][i];
                if (!tg->key) continue;
                uintptr_t a;
                if (CacheLookup(tg->key, &a)) continue;
                CacheStore(tg->key, Sig::Resolve(tg));
            }
    }

    uintptr_t Sig::Get(const char* key)
    {
        if (!key) return 0;

        uint64_t now = MonotonicMs();
        for (int i = 0; i < g_nCache; ++i) {
            if (!g_cache[i].key || strcmp(g_cache[i].key, key) != 0) continue;
            if (g_cache[i].addr) return g_cache[i].addr;
            if (g_cache[i].tries >= kSigMaxTries) return 0;
            if (now - g_cache[i].failMs < kSigRetryMs) return 0;
            break;
        }

        const CCTarget* tg = FindTarget(key);
        if (!tg) return 0;

        uintptr_t a = Sig::Resolve(tg);
        if (a) { CacheStore(key, a); return a; }

        for (int i = 0; i < g_nCache; ++i) {
            if (!g_cache[i].key || strcmp(g_cache[i].key, key) != 0) continue;
            ++g_cache[i].tries;
            g_cache[i].failMs = now;
            if (g_cache[i].tries == kSigMaxTries)
                Log::Debug("[CC-SIG] '%s' unresolved after %d attempts "
                           "(module not mapped or pattern drift)\n",
                           key, kSigMaxTries);
            return 0;
        }
        if (g_nCache < kMaxCache) {
            g_cache[g_nCache].key = key;
            g_cache[g_nCache].addr = 0;
            g_cache[g_nCache].failMs = now;
            g_cache[g_nCache].tries = 1;
            ++g_nCache;
            Log::Debug("[CC-SIG] '%s' unresolved (module not mapped or pattern drift), "
                       "retrying up to %d times\n", key, kSigMaxTries);
        }
        return 0;
    }
}
