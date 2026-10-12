# xinput.retro

A drop-in `xinput9_1_0.dll` that gives the Steam builds of No Man's Sky the same XInput controller support the GOG builds have, without Steam Input. One DLL covers every build and needs no per-version offsets.

## How it works

Every NMS executable, GOG or Steam, from 1.03 to 4.13, imports `XInputGetState` and `XInputSetState` from `xinput9_1_0.dll`. A copy in the game's `Binaries` folder is loaded ahead of the system one, before any game code runs, which makes it the one hook point that is guaranteed in every build. A `version.dll` proxy would depend on some other DLL happening to pull it in. The three XInput exports are forwarded straight to the system `xinput1_4.dll`.

Steam builds from at least Beyond 2.16 on create a `cTkInputManagerSteam`, a subclass of the `cTkInputManager` the GOG build uses. The subclass calls the base class and then layers Steam Input on top: it initializes `SteamInput001` (2.x) or `SteamInput006` (4.x), polls `GetConnectedControllers` every 32 frames, runs a Steam Input action poll before each button and axis read, and feeds Steam Input devices into the input ports. The base class and the whole GOG pad path (`cTkInputDeviceManager::ControllerDetectionTaskImpl`, `ProcessXInputPad`, `cTkPadXInput`) are still compiled into the Steam executable, at the same function sizes as GOG 4.13.

The DLL copies the base class's vtable over the Steam one. The game then runs the GOG input code for keyboard, mouse and pads, and Steam Input is never initialized. The two vtables are found in one of two ways.

- **With RTTI (3.x and 4.x).** Both classes are looked up by name (`.?AVcTkInputManagerSteam@@` and `.?AVcTkInputManager@@`), then their CompleteObjectLocators, then their vtables.
- **Without RTTI (2.x).** The DLL finds the `SteamInput0xx` interface string, the accessor that requests it, and that accessor's context. The Steam class's `Construct` calls the base `Construct` and then loads that context (`call <base>`, `lea rcx, [context]`), and `Update` does the same with the base `Update`. Each such pair gives one slot of each vtable. A vtable starts at the nearest address at or below that slot which code loads, the constructor's `lea`, and ends where the next loaded one starts. With the RTTI path switched off, this finder gives exactly the RTTI answer on 3.75, 3.89 and 4.13.

The patch runs from a hook on the executable's `_initterm_e` import, which the C runtime startup calls once, after SteamStub has decrypted the code of the wrapped `NMS.exe` and before any static constructor or `WinMain`. Static-CRT builds (1.x) have no such import and are checked straight from `DllMain`.

The destructor slot, where there is one (4.13), is copied along with the rest. The game's sized `operator delete` ignores the size, so the only effect is that the Steam-only members are not destroyed at shutdown.

## What it does per build

| Builds | What happens |
|--------|--------------|
| Steam 2.16 Beyond (wrapped and unpacked) | Patched through the Steam Input code, 14 slots |
| Steam 3.75, 3.89, 4.13 (wrapped, unpacked, and the March build) | Patched through RTTI, 14 slots in 3.x and 17 in 4.13 |
| Every GOG build | Left alone, there is no Steam class |
| Steam 1.x (up to 1.38) | Left alone, there is no Steam class and nothing to fix |

The 1.x Steam builds already read XInput exactly like GOG. In 1.38 the pad enumeration and read functions are identical between the two stores, and the Steam build's input update runs that XInput path first, then adds Steam Controller actions only when Steam reports a controller handle. [steam_api64.retro](https://github.com/NoMansSkyRetro/steam_api64.retro) reports none, so those builds use XInput alone.

Steam builds between 2.16 and 3.75 were not available to test. Either finder covers them as long as the class or the `Construct` pattern is there, and anything else is left untouched.

## Install

Copy `xinput9_1_0.dll` into the game's `Binaries` folder next to `NMS.exe`. Remove it to go back to Steam Input.

If Steam Input is enabled for No Man's Sky in the Steam client, Steam hands the game its own virtual Xbox controller, which this path also reads. Turn Steam Input off for the game to read the controller directly.

To get a log, create an empty `xinput9_1_0.retro.log` next to the DLL. It records which vtables were found, how and how many slots were switched, or why nothing was done.

## Build

Run `build.bat` with Visual Studio 2019 or newer installed. Output is `build\xinput9_1_0.dll`. The only dependency is kernel32.

`python tests\check.py [dll] [E:\NMS]` maps every `NMS.exe` under the folder without starting it, runs the patch, and checks the result against vtables located independently from the file: through RTTI with pefile, or for 2.16 against the addresses found by hand. Wrapped executables without RTTI stay encrypted in this test and must come back untouched, and so must builds without the Steam class.
