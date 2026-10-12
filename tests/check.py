"""Check a built xinput9_1_0.dll against real executables without starting the game: each NMS.exe
is mapped with LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES), the DLL's RetroXInputPatch runs on it,
and the result is compared with vtables located independently from the file by pefile.

    python tests/check.py [path\\to\\xinput9_1_0.dll] [E:\\NMS]
"""
import ctypes, glob, os, re, struct, sys
from ctypes import wintypes
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
dll_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "xinput9_1_0.dll")
root = sys.argv[2] if len(sys.argv) > 2 else r"E:\NMS"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.LoadLibraryExW.restype = ctypes.c_void_p
k32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
k32.FreeLibrary.argtypes = [ctypes.c_void_p]
dll = ctypes.CDLL(os.path.abspath(dll_path))
dll.RetroXInputPatch.argtypes = [ctypes.c_void_p]
state = (ctypes.c_byte * 16)()
assert dll.XInputGetState(0, state) in (0, 1167), "XInputGetState forwarder broken"  # ok / not connected


# Builds without RTTI, located by hand: PE timestamp -> (Steam vtable rva, base vtable rva, slots).
# Only checked on unwrapped executables, since the DLL needs the code decrypted to find these.
KNOWN = {0x5DC1D304: (0x1E12738, 0x1E14760, 14)}  # 2.16 Beyond


def vtable(pe, mem, name):
    """(rva, slots) of the class's primary vtable, found from the file the way MSVC lays out RTTI."""
    td = mem.find(name + b"\0") - 16
    if td < 0:
        return None
    for m in re.finditer(re.escape(struct.pack("<I", td)), mem):
        col = m.start() - 12
        if col % 4 == 0 and struct.unpack_from("<6I", mem, col)[:2] == (1, 0) and struct.unpack_from("<I", mem, col + 20)[0] == col:
            ref = mem.find(struct.pack("<Q", pe.OPTIONAL_HEADER.ImageBase + col))
            code = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize) for s in pe.sections if s.Characteristics & 0x20000000]
            vt, n = ref + 8, 0
            while any(a <= struct.unpack_from("<Q", mem, vt + 8 * n)[0] - pe.OPTIONAL_HEADER.ImageBase < b for a, b in code):
                n += 1
            return vt, n
    return None


exes = sorted(set(glob.glob(os.path.join(root, "*", "Binaries", "NMS.exe*")) + glob.glob(os.path.join(root, "*", "*", "Binaries", "NMS.exe*"))))
exes = [e for e in exes if e.endswith(".exe")]
assert exes, "no NMS.exe under " + root
patched = 0
for exe in exes:
    pe = pefile.PE(exe, fast_load=True)
    mem = pe.get_memory_mapped_image()
    base, steam = vtable(pe, mem, b".?AVcTkInputManager@@"), vtable(pe, mem, b".?AVcTkInputManagerSteam@@")
    known = KNOWN.get(pe.FILE_HEADER.TimeDateStamp)
    if not steam and known and not any(s.Name.startswith(b".bind") for s in pe.sections):
        steam, base = (known[0], known[2]), (known[1], known[2])
    pe.close()
    h = k32.LoadLibraryExW(exe, None, 1)  # DONT_RESOLVE_DLL_REFERENCES
    assert h, "could not map %s (error %d)" % (exe, ctypes.get_last_error())
    try:
        n = dll.RetroXInputPatch(h)
        if steam and base:
            want = min(base[1], steam[1])
            got_base = ctypes.string_at(h + base[0], want * 8)
            got_steam = ctypes.string_at(h + steam[0], want * 8)
            assert n == want and got_steam == got_base, "%s: patched %d slots, expected %d, vtables equal: %s" % (exe, n, want, got_steam == got_base)
            patched += 1
        else:
            assert n == 0, "%s has no cTkInputManagerSteam but %d slots were patched" % (exe, n)
        print("%-90s %s" % (exe, "patched %d slots" % n if n else "left alone"))
    finally:
        k32.FreeLibrary(h)
print("ok, %d executables, %d patched" % (len(exes), patched))
