// Drop-in xinput9_1_0.dll for No Man's Sky. Every build, GOG or Steam, imports XInputGetState and
// XInputSetState from this DLL, so it loads before any game code runs.
//
// Steam builds from at least Beyond 2.16 on differ from GOG's in two places, and this DLL undoes
// both without build-specific offsets:
//
// 1. They construct a cTkInputManagerSteam, which routes controllers through Steam Input. The base
//    cTkInputManager it derives from is the class the GOG build uses, and it is still compiled
//    into the Steam executable, so the base vtable is copied over the Steam one. The two vtables
//    are found through MSVC RTTI by class name (3.x on), or, in builds compiled without RTTI
//    (2.x), through the code that initializes Steam Input.
// 2. Their LoadBindings never registers the Xbox pad bindings, so the XInput pad is detected but
//    no input port reads it. Two calls in it are redirected to put that step back.
//
// GOG builds are left alone, and so are the 1.x Steam builds, which read XInput the same way GOG
// does, with Steam Controller layered on top.
#define NOMINMAX
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <vector>

#pragma comment(linker, "/export:XInputGetState=xinput1_4.XInputGetState")
#pragma comment(linker, "/export:XInputSetState=xinput1_4.XInputSetState")
#pragma comment(linker, "/export:XInputGetCapabilities=xinput1_4.XInputGetCapabilities")

static FILE* g_log;

static void say(const char* fmt, ...) {
    if (!g_log) return;
    va_list a;
    va_start(a, fmt);
    vfprintf(g_log, fmt, a);
    va_end(a);
    fputc('\n', g_log);
    fflush(g_log);
}

static bool put(void* at, const void* src, size_t n) {
    DWORD old;
    if (!VirtualProtect(at, n, PAGE_READWRITE, &old)) return false;
    memcpy(at, src, n);
    VirtualProtect(at, n, old, &old);
    return true;
}

static const char kPadBindings[] = "Metadata/Input/Bindings/GcInputBindings_XboxOne_Pad.mXml";
static const char kMouseBindings[] = "Metadata/Input/Bindings/GcInputBindings_Win_Mouse.mXml";

struct Image {
    BYTE* base;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sec;
    int nsec;

    explicit Image(HMODULE m) : base((BYTE*)m) {
        nt = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
        sec = IMAGE_FIRST_SECTION(nt);
        nsec = nt->FileHeader.NumberOfSections;
    }

    DWORD rva(const void* p) const { return DWORD((BYTE*)p - base); }

    // Whether p lies in a code section (code) or a data section (!code).
    bool in(UINT64 p, bool code) const {
        for (int i = 0; i < nsec; i++)
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == !code &&
                p - (UINT64)base - sec[i].VirtualAddress < sec[i].Misc.VirtualSize)
                return true;
        return false;
    }

    // First step-aligned address in a readable data section for which hit() holds.
    template <class F> BYTE* scan(size_t step, F hit) const {
        for (int i = 0; i < nsec; i++) {
            DWORD c = sec[i].Characteristics;
            if (!(c & IMAGE_SCN_MEM_READ) || (c & IMAGE_SCN_MEM_EXECUTE) || sec[i].Misc.VirtualSize < 64) continue;
            BYTE* p = base + sec[i].VirtualAddress;
            for (BYTE* end = p + sec[i].Misc.VirtualSize - 32; p < end; p += step)
                if (hit(p)) return p;
        }
        return nullptr;
    }

    template <class F> void each_code_byte(F f) const {
        for (int i = 0; i < nsec; i++) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) || sec[i].Misc.VirtualSize < 64) continue;
            BYTE* p = base + sec[i].VirtualAddress;
            for (BYTE* end = p + sec[i].Misc.VirtualSize - 16; p < end; p++) f(p);
        }
    }

    // The .pdata entry of the function containing rva, following chained unwind info to the
    // function's first chunk. Null if none.
    RUNTIME_FUNCTION* func(DWORD r) const {
        IMAGE_DATA_DIRECTORY& d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        RUNTIME_FUNCTION* rf = (RUNTIME_FUNCTION*)(base + d.VirtualAddress);
        size_t lo = 0, hi = d.Size / sizeof(RUNTIME_FUNCTION);
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (rf[mid].BeginAddress <= r) lo = mid + 1; else hi = mid;
        }
        if (!lo || r >= rf[lo - 1].EndAddress) return nullptr;
        RUNTIME_FUNCTION* f = &rf[lo - 1];
        for (int i = 0; i < 8; i++) {
            BYTE* ui = base + f->UnwindData;
            if (!((ui[0] >> 3) & UNW_FLAG_CHAININFO)) break;
            f = (RUNTIME_FUNCTION*)(ui + 4 + ((ui[2] + 1) & ~1) * 2);
        }
        return f;
    }
    DWORD func_start(DWORD r) const {
        RUNTIME_FUNCTION* f = func(r);
        return f ? f->BeginAddress : 0;
    }
    bool is_func(BYTE* p) const { return in((UINT64)p, true) && func_start(rva(p)) == rva(p); }
    static BYTE* call_target(BYTE* call) { return call + 5 + *(INT32*)(call + 1); }

    // The import address table slot of fn, imported from a DLL whose name starts with dll.
    void** import_slot(const char* dll, const char* fn) const {
        IMAGE_DATA_DIRECTORY& d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!d.Size) return nullptr;
        for (IMAGE_IMPORT_DESCRIPTOR* id = (IMAGE_IMPORT_DESCRIPTOR*)(base + d.VirtualAddress); id->Name; id++) {
            if (_strnicmp((char*)base + id->Name, dll, strlen(dll)) || !id->OriginalFirstThunk) continue;
            IMAGE_THUNK_DATA64* names = (IMAGE_THUNK_DATA64*)(base + id->OriginalFirstThunk);
            for (int i = 0; names[i].u1.AddressOfData; i++)
                if (!IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal) &&
                    !strcmp(((IMAGE_IMPORT_BY_NAME*)(base + names[i].u1.AddressOfData))->Name, fn))
                    return (void**)(base + id->FirstThunk) + i;
        }
        return nullptr;
    }

    // MSVC x64 RTTI: TypeDescriptor {vftable, spare, name} <- CompleteObjectLocator {1, offset,
    // cdOffset, TypeDescriptor rva, hierarchy rva, own rva} <- vtable[-1].
    UINT64* rtti_vtable(const char* name, int* slots) const {
        size_t n = strlen(name) + 1;
        BYTE* td = scan(1, [&](BYTE* p) { return *p == '.' && !memcmp(p, name, n); });
        if (!td) return nullptr;
        DWORD tdr = rva(td - 16);
        BYTE* col = scan(4, [&](BYTE* p) {
            DWORD* c = (DWORD*)p;
            return c[0] == 1 && c[1] == 0 && c[3] == tdr && c[5] == rva(p);
        });
        if (!col) return nullptr;
        BYTE* ref = scan(8, [&](BYTE* p) { return *(UINT64*)p == (UINT64)col; });
        if (!ref) return nullptr;
        UINT64* vt = (UINT64*)ref + 1;
        int k = 0;
        while (k < 64 && in(vt[k], true)) k++;
        *slots = k;
        return vt;
    }

    // Without RTTI the Steam class is found through its Construct override, which calls the base
    // Construct and then fetches Steam Input (Update does the same with the base Update):
    //     call  <base Construct>
    //     lea   rcx, [SteamInput accessor context]
    //     call  [SteamInternal_ContextInit]
    // Each such pair gives one slot of each vtable. A vtable starts at the nearest address at or
    // below that slot which code loads (the constructor's lea), and ends where the next one starts.
    // Needs decrypted code, so in wrapped builds it only works once the EXE has started.
    bool steam_input_vtables(UINT64** steam, UINT64** basevt, int* n) const {
        BYTE* str = scan(1, [](BYTE* p) { return *p == 'S' && !memcmp(p, "SteamInput0", 11); });
        if (!str) return false;
        std::vector<BYTE*> loads;  // data addresses that code loads through rip-relative lea/mov
        BYTE* init = nullptr;      // the accessor's SteamInternal_Init callback, which names the interface
        each_code_byte([&](BYTE* p) {
            if ((p[0] == 0x48 || p[0] == 0x4C) && (p[1] == 0x8D || p[1] == 0x8B) && (p[2] & 0xC7) == 5) {
                BYTE* t = p + 7 + *(INT32*)(p + 3);
                if (t == str && !init) {
                    DWORD f = func_start(rva(p));
                    if (f) init = base + f;
                }
                if (in((UINT64)t, false)) loads.push_back(t);
            }
        });
        if (!init) { say("%s found but no code uses it", (char*)str); return false; }
        BYTE* ctx = scan(8, [&](BYTE* p) { return *(UINT64*)p == (UINT64)init; });
        if (!ctx) { say("no accessor context for %s", (char*)str); return false; }
        std::sort(loads.begin(), loads.end());
        loads.erase(std::unique(loads.begin(), loads.end()), loads.end());

        std::vector<std::pair<BYTE*, BYTE*>> pairs;  // (Steam override, base function)
        each_code_byte([&](BYTE* p) {
            if (p[0] == 0xE8 && p[5] == 0x48 && p[6] == 0x8D && p[7] == 0x0D && p + 12 + *(INT32*)(p + 8) == ctx) {
                DWORD f = func_start(rva(p));
                if (f) pairs.push_back({base + f, p + 5 + *(INT32*)(p + 1)});
            }
        });
        auto start_of = [&](BYTE* slot) -> BYTE* {
            auto it = std::upper_bound(loads.begin(), loads.end(), slot);
            if (it == loads.begin()) return nullptr;
            BYTE* s = *--it;
            return slot - s < 64 * 8 && (slot - s) % 8 == 0 ? s : nullptr;
        };
        auto slots_from = [&](BYTE* s) {
            int k = 0;
            while (k < 64 && in(((UINT64*)s)[k], true) && (!k || !std::binary_search(loads.begin(), loads.end(), s + 8 * k))) k++;
            return k;
        };
        std::vector<std::pair<BYTE*, BYTE*>> votes;  // (Steam vtable, base vtable), one per agreeing slot
        for (auto& pr : pairs) {
            std::vector<BYTE*> ds, bs;
            scan(8, [&](BYTE* p) { if (*(UINT64*)p == (UINT64)pr.first) ds.push_back(p); return false; });
            scan(8, [&](BYTE* p) { if (*(UINT64*)p == (UINT64)pr.second) bs.push_back(p); return false; });
            for (BYTE* d : ds)
                for (BYTE* b : bs) {
                    BYTE *sd = start_of(d), *sb = start_of(b);
                    if (sd && sb && sd != sb && d - sd == b - sb) votes.push_back({sd, sb});
                }
        }
        std::sort(votes.begin(), votes.end());
        std::pair<BYTE*, BYTE*> best{};
        size_t most = 0;
        bool tie = false;
        for (size_t i = 0; i < votes.size();) {
            size_t j = i;
            while (j < votes.size() && votes[j] == votes[i]) j++;
            if (j - i > most) most = j - i, best = votes[i], tie = false;
            else if (j - i == most) tie = true;
            i = j;
        }
        if (!most || tie) { say("%s: %zu Construct-style calls, %zu vtable matches, no single answer", (char*)str, pairs.size(), votes.size()); return false; }
        *steam = (UINT64*)best.first;
        *basevt = (UINT64*)best.second;
        *n = std::min(slots_from(best.first), slots_from(best.second));
        return *n > 0;
    }

    // The Steam builds' cGcInputRemap::LoadBindings registers only the keyboard and mouse binding
    // files, where GOG's also registers kPadBindings and attaches it to the active input port as the
    // XInput pad. Finds the two calls that step goes next to:
    //     lea   rdx, [kMouseBindings]
    //     call  RegisterBindings          <- reg
    //     ...
    //     call  AddBindings               <- add, the first call to it after reg (active port)
    // AddBindings is the function called most often in the next 0x100 bytes (keyboard and mouse,
    // for two ports). 3.x and 4.x call a short overload of it; main is the full one it forwards to.
    bool pad_binding_sites(BYTE** reg, BYTE** add, BYTE** main) const {
        auto find = [&](const char* s, size_t n) { return scan(1, [&](BYTE* p) { return *p == 'M' && !memcmp(p, s, n); }); };
        if (find(kPadBindings, sizeof kPadBindings)) return false;  // GOG, which loads them already
        BYTE* str = find(kMouseBindings, sizeof kMouseBindings);
        if (!str) return false;
        BYTE* lea = nullptr;
        each_code_byte([&](BYTE* p) {
            if (!lea && p[0] == 0x48 && p[1] == 0x8D && p[2] == 0x15 && p + 7 + *(INT32*)(p + 3) == str) lea = p;
        });
        if (!lea) return false;
        *reg = nullptr;
        for (BYTE* p = lea + 7; p < lea + 0x20 && !*reg; p++)
            if (*p == 0xE8 && is_func(call_target(p))) *reg = p;
        if (!*reg) return false;
        std::vector<BYTE*> calls;
        for (BYTE* p = *reg + 5; p < *reg + 0x100; p++)
            if (*p == 0xE8 && is_func(call_target(p))) calls.push_back(p);
        int most = 0;
        for (BYTE* c : calls) {
            int k = (int)std::count_if(calls.begin(), calls.end(), [&](BYTE* d) { return call_target(d) == call_target(c); });
            if (k > most) most = k, *add = c;
        }
        if (most < 2) return false;
        *main = call_target(*add);
        RUNTIME_FUNCTION* f = func(rva(*main));
        if (f && f->EndAddress - f->BeginAddress < 0x80)
            for (BYTE* p = *main; p < base + f->EndAddress - 5; p++)
                if (*p == 0xE8 && is_func(call_target(p))) { *main = call_target(p); break; }
        return true;
    }
};

// Returns the number of vtable slots switched to the base class, 0 when there is nothing to do.
// Exported so tests\check.py can run it against executables mapped without starting them.
extern "C" __declspec(dllexport) int RetroXInputPatch(HMODULE exe) {
    Image im(exe);
    UINT64 *steam, *base = nullptr;
    int n = 0, ns = 0, nb = 0;
    const char* how = "RTTI";
    if ((steam = im.rtti_vtable(".?AVcTkInputManagerSteam@@", &ns))) {
        base = im.rtti_vtable(".?AVcTkInputManager@@", &nb);
        if (!base) { say("cTkInputManagerSteam found but cTkInputManager not, left alone"); return 0; }
        n = std::min(ns, nb);
    } else if (im.steam_input_vtables(&steam, &base, &n)) {
        how = "the Steam Input code";
    } else {
        say("no Steam input manager, nothing to do");
        return 0;
    }
    // The deleting destructor, where there is one, is copied too. The game's sized operator delete
    // ignores the size, so the only cost is that Steam-only members are not destroyed at shutdown.
    if (!put(steam, base, n * 8)) { say("VirtualProtect failed %lu", GetLastError()); return 0; }
    say("Steam input manager vtable at +%x now uses the base one at +%x (%d slots, found through %s)",
        im.rva(steam), im.rva(base), n, how);
    return n;
}

typedef int (*register_fn)(void* self, const char* path, void*, void*);
typedef int (*add_fn)(void* port, INT64, INT64, INT64, INT64, INT64, INT64);
static register_fn g_register;
static add_fn g_add, g_add_main;
static int g_pad_bindings = -1;

static int register_hook(void* self, const char* path, void* a, void* b) {
    int id = g_register(self, path, a, b);
    g_pad_bindings = g_register(self, kPadBindings, a, b);
    return id;
}

static int add_hook(void* port, INT64 a, INT64 b, INT64 c, INT64 d, INT64 e, INT64 f) {
    int r = g_add(port, a, b, c, d, e, f);
    if (g_pad_bindings >= 0) {
        // EButtonPad (3), EPad_XInput (1), no hand, the pad bindings, nothing chained either side
        g_add_main(port, 3, 1, 0, g_pad_bindings, -1, -1);
        say("Xbox pad bindings %d attached to input port %p", g_pad_bindings, port);
        g_pad_bindings = -1;
    }
    return r;
}

// Points the rel32 call at site to fn, through a jump stub allocated within reach of the image.
static bool redirect_call(BYTE* image, BYTE* site, void* fn) {
    static BYTE* stubs;
    static int used;
    if (stubs && (stubs > site || site - stubs > 0x70000000)) stubs = nullptr, used = 0;  // another image
    UINT64 lowest = (UINT64)image > 0x70000000 ? (UINT64)image - 0x70000000 : 0x10000;
    for (UINT64 a = ((UINT64)image & ~0xFFFFull) - 0x10000; !stubs && a > lowest; a -= 0x10000)
        stubs = (BYTE*)VirtualAlloc((void*)a, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stubs || used == 0x1000 / 16) return false;
    BYTE* stub = stubs + 16 * used++;
    BYTE jmp[14] = {0xFF, 0x25};  // jmp [rip+0], followed by the target
    memcpy(jmp + 6, &fn, 8);
    memcpy(stub, jmp, sizeof jmp);
    INT32 rel = INT32(stub - (site + 5));
    DWORD old;
    if (!VirtualProtect(site + 1, 4, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(site + 1, &rel, 4);
    VirtualProtect(site + 1, 4, old, &old);
    FlushInstructionCache(GetCurrentProcess(), site, 5);
    return true;
}

// Puts back the step that registers the Xbox pad bindings, which every Steam build from 2.16 on
// leaves out of LoadBindings. Without it the pad is detected but no input port reads it. The
// bindings file still ships in the Steam paks. Returns 1 when both calls were redirected, 0 when
// there is nothing to do. Exported so tests\check.py can run it on mapped executables.
extern "C" __declspec(dllexport) int RetroXInputBindings(HMODULE exe) {
    Image im(exe);
    BYTE *reg, *add, *main;
    if (!im.pad_binding_sites(&reg, &add, &main)) { say("pad bindings already loaded or LoadBindings not found, left alone"); return 0; }
    g_register = (register_fn)Image::call_target(reg);
    g_add = (add_fn)Image::call_target(add);
    g_add_main = (add_fn)main;
    if (!redirect_call(im.base, reg, (void*)&register_hook) || !redirect_call(im.base, add, (void*)&add_hook)) {
        say("could not redirect the LoadBindings calls");
        return 0;
    }
    say("LoadBindings calls at +%x and +%x now also load the Xbox pad bindings (AddBindings at +%x)",
        im.rva(reg), im.rva(add), im.rva(main));
    return 1;
}

typedef int(__cdecl* initterm_e_fn)(void*, void*);
static initterm_e_fn g_initterm_e;
static void** g_initterm_e_slot;

// The EXE's CRT startup calls _initterm_e once, after SteamStub has decrypted the code and before
// any static constructor or WinMain runs.
static int __cdecl initterm_e_hook(void* first, void* last) {
    put(g_initterm_e_slot, &g_initterm_e, sizeof(void*));
    RetroXInputPatch(GetModuleHandleA(nullptr));
    RetroXInputBindings(GetModuleHandleA(nullptr));
    return g_initterm_e(first, last);
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD why, LPVOID) {
    if (why != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(self);
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(self, path, MAX_PATH - 16);
    if (len && len < MAX_PATH - 16) {
        strcpy(strrchr(path, '.'), ".retro.log");
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) g_log = fopen(path, "w");
    }
    // Static-CRT builds (1.x) have no _initterm_e import and nothing that needs their code read.
    HMODULE exe = GetModuleHandleA(nullptr), owner;
    void** slot = Image(exe).import_slot("api-ms-win-crt-runtime-", "_initterm_e");
    void* hook = (void*)&initterm_e_hook;
    if (slot && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)*slot, &owner)) {
        g_initterm_e = (initterm_e_fn)*slot;
        g_initterm_e_slot = slot;
        if (put(slot, &hook, sizeof(void*))) return TRUE;
    }
    RetroXInputPatch(exe);
    RetroXInputBindings(exe);
    return TRUE;
}
