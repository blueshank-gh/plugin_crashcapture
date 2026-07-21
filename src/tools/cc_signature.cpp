// cc_signature - see cc_signature.h.

#include "tools/cc_signature.h"
#include <string.h>

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

    static int ScanCore(const CCModule* m, const CCPattern* p, uintptr_t* out, int max)
    {
        if (!m || !p || p->len <= 0 || max <= 0) return 0;
        const int len = p->len;
        if (m->size < (size_t)len) return 0;

        int skip[256];
        BuildSkip(p, skip);

        const uintptr_t base = m->base;
        const uintptr_t end  = m->base + m->size;
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

    static const CCTarget* g_tables[kMaxTables];
    static int g_tableCount[kMaxTables];
    static int g_nTables = 0;

    struct Cached { const char* key; uintptr_t addr; };
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
        uintptr_t a;
        if (CacheLookup(key, &a)) return a;

        const CCTarget* tg = FindTarget(key);
        if (!tg) return 0;
        a = Sig::Resolve(tg);
        CacheStore(key, a);
        return a;
    }
}
