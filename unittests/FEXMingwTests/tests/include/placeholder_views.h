#pragma once

#include <windows.h>

// Views mapped into a placeholder: no other allocation (FEX's code buffers among them) can take the address while no
// view is mapped there, so a test can map views at the same address again and again.
// Looked up at run time: the mingw headers and import libraries used here only declare them for Windows 10 RS4+.
namespace PlaceholderViews {
using VirtualAlloc2Fn = PVOID(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, void*, ULONG);
using MapViewOfFile3Fn = PVOID(WINAPI*)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, void*, ULONG);
using UnmapViewOfFile2Fn = BOOL(WINAPI*)(HANDLE, PVOID, ULONG);

inline MapViewOfFile3Fn pMapViewOfFile3;
inline UnmapViewOfFile2Fn pUnmapViewOfFile2;

// Returns nullptr if the placeholder functions are missing.
inline void* Reserve(SIZE_T Size) {
  auto* KernelBase = GetModuleHandleW(L"kernelbase.dll");
  auto pVirtualAlloc2 = reinterpret_cast<VirtualAlloc2Fn>(GetProcAddress(KernelBase, "VirtualAlloc2"));
  pMapViewOfFile3 = reinterpret_cast<MapViewOfFile3Fn>(GetProcAddress(KernelBase, "MapViewOfFile3"));
  pUnmapViewOfFile2 = reinterpret_cast<UnmapViewOfFile2Fn>(GetProcAddress(KernelBase, "UnmapViewOfFile2"));
  if (!pVirtualAlloc2 || !pMapViewOfFile3 || !pUnmapViewOfFile2) {
    return nullptr;
  }
  return pVirtualAlloc2(GetCurrentProcess(), nullptr, Size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0);
}

inline bool Map(HANDLE Section, void* Placeholder, SIZE_T Size, ULONG Prot) {
  return pMapViewOfFile3(Section, GetCurrentProcess(), Placeholder, 0, Size, MEM_REPLACE_PLACEHOLDER, Prot, nullptr, 0) == Placeholder;
}

// Unmaps the view and keeps the placeholder.
inline void Unmap(void* View) {
  pUnmapViewOfFile2(GetCurrentProcess(), View, MEM_PRESERVE_PLACEHOLDER);
}

// Unmaps the view and releases the address.
inline void Release(void* View) {
  pUnmapViewOfFile2(GetCurrentProcess(), View, 0);
}
} // namespace PlaceholderViews
