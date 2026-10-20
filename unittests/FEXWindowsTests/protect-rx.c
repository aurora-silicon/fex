#include <windows.h>
#include <stdio.h>
static volatile LONG faults;
static unsigned char* page;
static LONG CALLBACK handler(EXCEPTION_POINTERS* ex) {
  if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || ex->ExceptionRecord->NumberParameters < 2 ||
      ex->ExceptionRecord->ExceptionInformation[0] != 1 || ex->ExceptionRecord->ExceptionInformation[1] != (ULONG_PTR)(page + 128)) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  DWORD old;
  InterlockedIncrement(&faults);
  if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READWRITE, &old)) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  return EXCEPTION_CONTINUE_EXECUTION;
}
int main(void) {
  page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!page) {
    return 2;
  }
  const unsigned char code[] = {0xb8, 0x7b, 0, 0, 0, 0xc3};
  CopyMemory(page, code, sizeof(code));
  if (((int (*)(void))page)() != 123) {
    return 3;
  }
  DWORD old;
  if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old)) {
    return 4;
  }
  void* veh = AddVectoredExceptionHandler(1, handler);
  if (!veh) {
    return 5;
  }
  *(volatile unsigned char*)(page + 128) = 42;
  printf("write_faults=%ld value=%u\n", faults, page[128]);
  RemoveVectoredExceptionHandler(veh);
  VirtualFree(page, 0, MEM_RELEASE);
  return faults == 1 ? 0 : 1;
}
