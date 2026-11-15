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

    // Looks the import up by name, so a slot another plugin has already replaced
    // is still found and its hook stays chained behind ours.
    GetKeyStateFn* FindKeyStateByName()
    {
        auto base = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            return nullptr;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        // Packers leave stale RVAs behind, so each one is range checked before use.
        const size_t imageSize = nt->OptionalHeader.SizeOfImage;
        auto at = [&](size_t rva, size_t size) -> uint8_t*
        {
            return rva && rva <= imageSize && size <= imageSize - rva ? base + rva : nullptr;
        };

        size_t rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        for (;; rva += sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            auto desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(at(rva, sizeof(IMAGE_IMPORT_DESCRIPTOR)));
            if (!desc || !desc->Name || !desc->FirstThunk)
                return nullptr;
            auto dll = reinterpret_cast<const char*>(at(desc->Name, sizeof("user32.dll")));
            if (!dll || _strnicmp(dll, "user32.dll", sizeof("user32.dll")) != 0)
                continue;

            for (size_t offset = 0;; offset += sizeof(IMAGE_THUNK_DATA))
            {
                auto name = reinterpret_cast<const IMAGE_THUNK_DATA*>(at(desc->OriginalFirstThunk + offset, sizeof(IMAGE_THUNK_DATA)));
                auto slot = reinterpret_cast<IMAGE_THUNK_DATA*>(at(desc->FirstThunk + offset, sizeof(IMAGE_THUNK_DATA)));
                if (!name || !slot || !name->u1.AddressOfData)
                    break;
                if (IMAGE_SNAP_BY_ORDINAL(name->u1.Ordinal))
                    continue;
                auto import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                    at(name->u1.AddressOfData, offsetof(IMAGE_IMPORT_BY_NAME, Name) + sizeof("GetKeyState")));
                if (import && std::strncmp(import->Name, "GetKeyState", sizeof("GetKeyState")) == 0)
                    return reinterpret_cast<GetKeyStateFn*>(&slot->u1.Function);
            }
        }
    }

    // Packed/Steam executables hide or replace the PE import directory: scan the
    // unpacked USER32.dll IAT slice around the resolved CreateWindowExA slot.
    GetKeyStateFn* FindKeyStateByAddress(decltype(&CreateWindowExA)* windowImport)
    {
        auto user32 = GetModuleHandleW(L"user32.dll");
        auto target = user32 ? reinterpret_cast<GetKeyStateFn>(GetProcAddress(user32, "GetKeyState")) : nullptr;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!target || VirtualQuery(windowImport, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT)
            return nullptr;

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
        return nullptr;
    }

    // A pattern only proves that something is read or called next to VK_LSHIFT.
    // Accept the operand only if it is an import slot of the game that can hold
    // GetKeyState, so a game variable or another import is never overwritten.
    bool IsKeyStateSlot(GetKeyStateFn* slot)
    {
        auto exe = GetModuleHandleW(nullptr);
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(slot, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT ||
            mbi.AllocationBase != exe || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return false;

        // The slot has to point at code of another module
        auto target = *slot;
        HMODULE owner = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(target), &owner) || !owner || owner == exe)
            return false;

        // Inside USER32 it must be the export itself. Anywhere else it is a shim
        // or another plugin's replacement, which cannot be identified further.
        auto user32 = GetModuleHandleW(L"user32.dll");
        return owner != user32 || target == reinterpret_cast<GetKeyStateFn>(GetProcAddress(user32, "GetKeyState"));
    }

    // Last resort: the operand of the instruction that calls or loads the import
    // for the VK_LSHIFT poll. Used only if every match agrees on one valid slot.
    GetKeyStateFn* FindKeyStateByPattern()
    {
        GetKeyStateFn* found = nullptr;
        bool ambiguous = false;
        auto consider = [&](GetKeyStateFn* slot)
        {
            if (!IsKeyStateSlot(slot))
                return;
            ambiguous |= found && found != slot;
            found = slot;
        };

        // push VK_LSHIFT; call [slot]
        auto direct = hook::pattern("68 A0 00 00 00 FF 15 ? ? ? ?");
        for (size_t i = 0; i < direct.size(); ++i)
            consider(ReadOperand<GetKeyStateFn*>(direct.get(i).get<const uint8_t>(5), 2));

        // mov reg, [slot]; push VK_LSHIFT
        auto reg = hook::pattern("8B ? ? ? ? ? 68 A0 00 00 00");
        for (size_t i = 0; i < reg.size(); ++i)
        {
            auto insn = reg.get(i).get<const uint8_t>();
            if ((insn[1] & 0xC7) == 0x05)
                consider(ReadOperand<GetKeyStateFn*>(insn, 2));
        }

        return ambiguous ? nullptr : found;
    }

    GetKeyStateFn* ResolveKeyStateImport(decltype(&CreateWindowExA)* windowImport)
    {
        if (auto slot = FindKeyStateByName())
            return slot;
        if (auto slot = FindKeyStateByAddress(windowImport))
            return slot;
        return FindKeyStateByPattern();
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
    else
        OutputDebugStringA("WindowedMode: GetKeyState import not found, Shift can leak into the unfocused game.\n");

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
