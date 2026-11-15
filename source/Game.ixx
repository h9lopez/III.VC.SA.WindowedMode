module;
#include <cstddef>
#include <cstring>
#include "Bindings.h"
#include "Settings.h"

export module Game;

import WindowedMode;
import GTA3;
import GTAVC;
import GTASA;

namespace
{
    std::unique_ptr<WindowedMode> controller;

    void __cdecl ChangeResolution(DWORD mode)
    {
        inst->ChangeResolution(mode);
    }

    using GetKeyStateFn = decltype(&::GetKeyState);

    GetKeyStateFn* ResolveKeyStateImport(decltype(&CreateWindowExA)* windowImport)
    {
        // Resolve through the Import Name Table first so another plugin's earlier IAT
        // hook on GetKeyState is preserved and chained rather than missed.
        if (auto base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr)))
        {
            auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0)
            {
                auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                {
                    const auto imageSize = nt->OptionalHeader.SizeOfImage;
                    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                    if (dir.VirtualAddress && dir.Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR) &&
                        dir.VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= imageSize)
                    {
                        for (auto desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
                            reinterpret_cast<const uint8_t*>(desc + 1) <= base + imageSize && desc->Name && desc->FirstThunk;
                            ++desc)
                        {
                            if (!desc->OriginalFirstThunk || desc->Name + 11 > imageSize ||
                                desc->OriginalFirstThunk >= imageSize || desc->FirstThunk >= imageSize ||
                                _strnicmp(reinterpret_cast<const char*>(base + desc->Name), "user32.dll", 11) != 0)
                                continue;

                            auto orig = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
                            auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(const_cast<uint8_t*>(base) + desc->FirstThunk);
                            for (; reinterpret_cast<const uint8_t*>(orig + 1) <= base + imageSize &&
                                   reinterpret_cast<const uint8_t*>(thunk + 1) <= base + imageSize &&
                                   orig->u1.AddressOfData; ++orig, ++thunk)
                            {
                                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
                                    continue;
                                if (orig->u1.AddressOfData + offsetof(IMAGE_IMPORT_BY_NAME, Name) + 12 > imageSize)
                                    continue;
                                auto byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + orig->u1.AddressOfData);
                                if (std::strncmp(byName->Name, "GetKeyState", 12) == 0)
                                    return reinterpret_cast<GetKeyStateFn*>(&thunk->u1.Function);
                            }
                        }
                    }
                }
            }
        }

        // Packed/Steam executables hide or replace the PE import directory; scan the
        // unpacked USER32.dll IAT slice anchored on the resolved CreateWindowExA slot.
        if (auto user32 = GetModuleHandleW(L"user32.dll"))
        {
            if (auto target = reinterpret_cast<GetKeyStateFn>(GetProcAddress(user32, "GetKeyState")))
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(windowImport, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_COMMIT)
                {
                    auto begin = static_cast<GetKeyStateFn*>(mbi.BaseAddress);
                    auto end = reinterpret_cast<GetKeyStateFn*>(static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize);
                    auto slot = reinterpret_cast<GetKeyStateFn*>(windowImport);
                    while (slot > begin && *(slot - 1) != nullptr)
                        --slot;
                    for (; slot < end && *slot != nullptr; ++slot)
                    {
                        if (*slot == target)
                            return slot;
                    }
                }
            }
        }

        auto direct = hook::pattern("68 A0 00 00 00 FF 15 ? ? ? ?");
        if (direct.size() == 1)
            return ReadOperand<GetKeyStateFn*>(direct.get_first(5), 2);

        auto reg = hook::pattern("8B ? ? ? ? ? 68 A0 00 00 00");
        for (size_t i = 0; i < reg.size(); ++i)
        {
            auto insn = reg.get(i).get<const uint8_t>();
            if ((insn[1] & 0xC7) == 0x05)
                return ReadOperand<GetKeyStateFn*>(insn, 2);
        }

        return nullptr;
    }
}

export void InitializeGame()
{
    if (controller)
        return;
    // Fullscreen is the game's own exclusive mode: nothing to change
    if (Settings().Int("MAIN.WindowMode") == WindowedMode::Fullscreen)
        return;
    // Resolve the complete profile first, so an unsupported executable receives
    // no partial menu patches. III and VC share the same Win32 class name.
    GameBindings game;
    if (!hook::pattern("83 3D ? ? ? ? 08 75 ? E8 ? ? ? ? 85 C0 89 44 24 08").empty())
        game = ResolveGTASA();
    else if (!hook::pattern("8B 35 ? ? ? ? 6A 00 55 6A 00").empty())
        game = ResolveGTAVC();
    else
        game = ResolveGTA3();

    ResolveD3DCalls(game);

    auto window = hook::pattern("68 00 00 CF 00 ? ? 6A 00 FF 15 ? ? ? ?");
    if (window.size() != 1)
        throw std::runtime_error("Missing or ambiguous executable pattern.");
    auto windowCall = reinterpret_cast<uintptr_t>(window.get_first(9));
    auto windowImport = ReadOperand<decltype(&CreateWindowExA)*>(windowCall, 2);
    WindowedMode::createWindow = *windowImport;
    auto keyStateImport = ResolveKeyStateImport(windowImport);
    if (keyStateImport)
        WindowedMode::oriGetKeyState = *keyStateImport;

    controller = std::make_unique<WindowedMode>(game);
    inst = controller.get();
    // Changes from editors and overlays come from other threads: apply them on the window's thread
    for (auto id : { "MAIN.WindowMode", "MAIN.ConfineCursor", "WINDOW.Width", "WINDOW.Height" })
    {
        Settings().OnChange(id, []()
        {
            if (inst && inst->window)
                PostMessageA(inst->window, WindowedMode::WM_APPLY_SETTINGS, 0, 0);
        });
    }
    // Replace only the executable's six-byte indirect call, preserving its
    // existing imported target (including any other plugin's replacement).
    injector::MakeNOP(windowCall, 6, true);
    injector::MakeCALL(windowCall, WindowedMode::InitWindow, true);
    if (keyStateImport)
        injector::WriteMemory(keyStateImport, &WindowedMode::GetFocusedKeyState, true);
    if (game.title == GameTitle::GTASA)
    {
        injector::MakeCALL(game.menuResolutionCall, WindowedMode::ChangeResolutionSA, true);
        injector::MakeCALL(game.changeVideoModeCall, WindowedMode::ChangeVideoModeSA, true);
        injector::WriteMemory<uint8_t>(game.deviceDialog, 0xEB, true);
        if (game.mouseRecenter) injector::MakeNOP(game.mouseRecenter, 5, true);
        injector::MakeJMP(game.grabScreen, WindowedMode::GrabScreenSA, true);
    }
    else
    {
        injector::MakeCALL(game.menuResolutionCall, ChangeResolution, true);
        if (game.title == GameTitle::GTA3)
        {
            injector::WriteMemory<uint8_t>(game.resolutionColor, 0xEB, true);
            injector::MakeNOP(game.resolutionEnable, 6, true);
        }
        else
        {
            injector::WriteMemory<uint16_t>(game.resolutionColor, 0xE990, true);
            injector::MakeNOP(game.resolutionEnable, 2, true);
        }
    }
}
