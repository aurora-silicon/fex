// SPDX-License-Identifier: MIT
#define NTDDI_VERSION 0x0A000005
#define WINAPI
#define WINBASEAPI

#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <ntstatus.h>
#include <winternl.h>
#include <windows.h>
#include <processenv.h>
#include <atomic>
#include <iterator>
#include "../Priv.h"

// FEX runs on the guest's own threads, so it must not block on anything that parks the thread with
// NtWaitForAlertByThreadId: Wine's (and Windows') RtlWaitOnAddress, and the SRW locks, condition variables and
// critical sections built on it. That alert is a single per-thread flag shared with the guest. The guest's
// RtlWaitOnAddress queues itself and then makes its NtWaitForAlertByThreadId syscall; if FEX blocks on one of those
// locks in between (compiling or linking a block under a contended CodeInvalidationMutex, say), FEX's wait consumes
// the guest's wakeup, and the guest thread sleeps forever on a lock that is free. So everything FEX blocks on here
// parks on an NT event of its own and never touches the thread alert.
namespace {
struct Waiter {
  Waiter* Next;
  Waiter* Prev;
  const volatile void* Address;
  HANDLE Event;
  std::atomic<bool> Woken;
};

struct alignas(64) Bucket {
  std::atomic<uint32_t> Lock;
  Waiter Head; // Circular list; Head.Next is null until first use.
};

Bucket Buckets[256];

Bucket& GetBucket(const volatile void* Address) {
  return Buckets[(reinterpret_cast<uintptr_t>(Address) >> 4) % std::size(Buckets)];
}

void LockBucket(Bucket& B) {
  while (B.Lock.exchange(1, std::memory_order_acquire)) {
    while (B.Lock.load(std::memory_order_relaxed)) {
      YieldProcessor();
    }
  }
  if (!B.Head.Next) {
    B.Head.Next = B.Head.Prev = &B.Head;
  }
}

void UnlockBucket(Bucket& B) {
  B.Lock.store(0, std::memory_order_release);
}

// Auto-reset events, unsignaled whenever they are in the pool.
std::atomic<uint32_t> EventPoolLock;
HANDLE EventPool[1024];
size_t EventPoolCount;

HANDLE AcquireEvent() {
  HANDLE Event {};
  while (EventPoolLock.exchange(1, std::memory_order_acquire)) {
    YieldProcessor();
  }
  if (EventPoolCount) {
    Event = EventPool[--EventPoolCount];
  }
  EventPoolLock.store(0, std::memory_order_release);
  if (!Event && NtCreateEvent(&Event, EVENT_ALL_ACCESS, nullptr, SynchronizationEvent, FALSE)) {
    // No event means no way to park; fail loudly rather than spin or lose wakeups.
    __fastfail(0);
  }
  return Event;
}

void ReleaseEvent(HANDLE Event) {
  while (EventPoolLock.exchange(1, std::memory_order_acquire)) {
    YieldProcessor();
  }
  bool Pooled = EventPoolCount < std::size(EventPool);
  if (Pooled) {
    EventPool[EventPoolCount++] = Event;
  }
  EventPoolLock.store(0, std::memory_order_release);
  if (!Pooled) {
    NtClose(Event);
  }
}

bool AddressMatches(const volatile void* Address, const void* Compare, SIZE_T Size) {
  switch (Size) {
  case 1: return *static_cast<const volatile uint8_t*>(Address) == *static_cast<const uint8_t*>(Compare);
  case 2: return *static_cast<const volatile uint16_t*>(Address) == *static_cast<const uint16_t*>(Compare);
  case 4: return *static_cast<const volatile uint32_t*>(Address) == *static_cast<const uint32_t*>(Compare);
  case 8: return *static_cast<const volatile uint64_t*>(Address) == *static_cast<const uint64_t*>(Compare);
  }
  return false;
}

// WaitOnAddress semantics: returns false only on timeout. Spurious returns are allowed.
bool ParkOnAddress(const volatile void* Address, const void* Compare, SIZE_T Size, const LARGE_INTEGER* Timeout) {
  Bucket& B = GetBucket(Address);
  Waiter W;
  W.Address = Address;
  W.Event = AcquireEvent();
  W.Woken.store(false, std::memory_order_relaxed);

  LockBucket(B);
  // Compare under the bucket lock: a waker changes the value before it takes this lock, so it can't be missed.
  if (!AddressMatches(Address, Compare, Size)) {
    UnlockBucket(B);
    ReleaseEvent(W.Event);
    return true;
  }
  W.Prev = B.Head.Prev;
  W.Next = &B.Head;
  B.Head.Prev->Next = &W;
  B.Head.Prev = &W;
  UnlockBucket(B);

  NTSTATUS Status = NtWaitForSingleObject(W.Event, FALSE, const_cast<LARGE_INTEGER*>(Timeout));

  bool Woken = W.Woken.load(std::memory_order_acquire);
  if (!Woken) {
    LockBucket(B);
    Woken = W.Woken.load(std::memory_order_relaxed);
    if (!Woken) {
      W.Prev->Next = W.Next;
      W.Next->Prev = W.Prev;
    }
    UnlockBucket(B);
  }
  if (Woken && Status != STATUS_WAIT_0) {
    // A waker dequeued us just as the wait timed out and is about to signal; take that signal so the event goes
    // back to the pool unsignaled.
    NtWaitForSingleObject(W.Event, FALSE, nullptr);
  }
  ReleaseEvent(W.Event);
  return Woken || Status == STATUS_WAIT_0;
}

void UnparkAddress(const volatile void* Address, bool All) {
  Bucket& B = GetBucket(Address);
  HANDLE Events[64];
  bool More;
  do {
    size_t Count = 0;
    More = false;
    LockBucket(B);
    for (Waiter* W = B.Head.Next; W != &B.Head;) {
      Waiter* Next = W->Next;
      if (W->Address == Address) {
        if (Count == std::size(Events)) {
          More = true;
          break;
        }
        W->Prev->Next = W->Next;
        W->Next->Prev = W->Prev;
        Events[Count++] = W->Event;
        // After this store W may go away, so it is not touched again.
        W->Woken.store(true, std::memory_order_release);
        if (!All) {
          break;
        }
      }
      W = Next;
    }
    UnlockBucket(B);
    for (size_t i = 0; i < Count; ++i) {
      NtSetEvent(Events[i], nullptr);
    }
  } while (More);
}

LARGE_INTEGER* RelativeTimeout(DWORD Milliseconds, LARGE_INTEGER* Time) {
  if (Milliseconds == INFINITE) {
    return nullptr;
  }
  // A negative value indicates a relative time measured in 100ns intervals.
  Time->QuadPart = static_cast<LONGLONG>(Milliseconds) * -10000;
  return Time;
}

// SRW lock state, in the low 32 bits of the SRWLOCK: writer bit, waiters bit, reader count.
constexpr uint32_t SRW_WRITER = 1U << 31;
constexpr uint32_t SRW_WAITERS = 1U << 30;
constexpr uint32_t SRW_READERS = SRW_WAITERS - 1;
constexpr int SRW_SPINS = 64;

std::atomic<uint32_t>& Word(void* Ptr) {
  return *reinterpret_cast<std::atomic<uint32_t>*>(Ptr);
}

// Shared by exclusive and shared acquisition: Blocked are the state bits that stop this kind of acquire, Add is what it
// adds on success.
void AcquireSRW(PSRWLOCK SRWLock, uint32_t Blocked, uint32_t Add) {
  auto& State = Word(SRWLock);
  uint32_t Cur = State.load(std::memory_order_relaxed);
  int Spins = 0;
  for (;;) {
    if (!(Cur & Blocked)) {
      if (State.compare_exchange_weak(Cur, Cur + Add, std::memory_order_acquire, std::memory_order_relaxed)) {
        return;
      }
      continue;
    }
    if (Spins < SRW_SPINS) {
      ++Spins;
      YieldProcessor();
      Cur = State.load(std::memory_order_relaxed);
      continue;
    }
    if (!(Cur & SRW_WAITERS) && !State.compare_exchange_weak(Cur, Cur | SRW_WAITERS, std::memory_order_relaxed, std::memory_order_relaxed)) {
      continue;
    }
    Cur |= SRW_WAITERS;
    ParkOnAddress(&State, &Cur, sizeof(Cur), nullptr);
    Cur = State.load(std::memory_order_relaxed);
  }
}

bool TryAcquireSRW(PSRWLOCK SRWLock, uint32_t Blocked, uint32_t Add) {
  auto& State = Word(SRWLock);
  uint32_t Cur = State.load(std::memory_order_relaxed);
  while (!(Cur & Blocked)) {
    if (State.compare_exchange_weak(Cur, Cur + Add, std::memory_order_acquire, std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}

// Critical section, on the CRITICAL_SECTION's own fields: LockCount is 0 free, 1 held, 2 held with waiters.
// ntdll's convention is -1 free, so an object set up by RtlInitializeCriticalSection or a static -1 initializer
// deadlocks here. Only InitializeCriticalSection below may initialize objects these shims enter; nothing in FEX
// does otherwise.
std::atomic<uint32_t>& CSWord(LPCRITICAL_SECTION CS) {
  return *reinterpret_cast<std::atomic<uint32_t>*>(&CS->LockCount);
}

HANDLE CurrentThreadId() {
  return GetCurrentTEB()->ClientId.UniqueThread;
}
} // namespace

WINBOOL WaitOnAddress(volatile void* Address, void* CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds) {
  LARGE_INTEGER Time;
  if (ParkOnAddress(Address, CompareAddress, AddressSize, RelativeTimeout(dwMilliseconds, &Time))) {
    return TRUE;
  }
  SetLastError(ERROR_TIMEOUT);
  return FALSE;
}

void WakeByAddressAll(PVOID Address) {
  UnparkAddress(Address, true);
}

void WINAPI WakeByAddressSingle(PVOID Address) {
  UnparkAddress(Address, false);
}

DLLEXPORT_FUNC(void, InitializeSRWLock, (PSRWLOCK SRWLock)) {
  SRWLock->Ptr = nullptr;
}

void AcquireSRWLockExclusive(PSRWLOCK SRWLock) {
  AcquireSRW(SRWLock, SRW_WRITER | SRW_READERS, SRW_WRITER);
}

void ReleaseSRWLockExclusive(PSRWLOCK SRWLock) {
  auto& State = Word(SRWLock);
  if (State.fetch_and(~(SRW_WRITER | SRW_WAITERS), std::memory_order_release) & SRW_WAITERS) {
    UnparkAddress(&State, true);
  }
}

void AcquireSRWLockShared(PSRWLOCK SRWLock) {
  AcquireSRW(SRWLock, SRW_WRITER, 1);
}

void ReleaseSRWLockShared(PSRWLOCK SRWLock) {
  auto& State = Word(SRWLock);
  uint32_t Old = State.fetch_sub(1, std::memory_order_release);
  // The last reader out wakes whoever waits; they recheck and set the waiters bit again if they still have to wait.
  if ((Old & SRW_READERS) == 1 && (Old & SRW_WAITERS) && (State.fetch_and(~SRW_WAITERS, std::memory_order_relaxed) & SRW_WAITERS)) {
    UnparkAddress(&State, true);
  }
}

DLLEXPORT_FUNC(BOOLEAN, TryAcquireSRWLockShared, (PSRWLOCK SRWLock)) {
  return TryAcquireSRW(SRWLock, SRW_WRITER, 1);
}

DLLEXPORT_FUNC(BOOLEAN, TryAcquireSRWLockExclusive, (PSRWLOCK SRWLock)) {
  return TryAcquireSRW(SRWLock, SRW_WRITER | SRW_READERS, SRW_WRITER);
}

DLLEXPORT_FUNC(void, InitializeCriticalSection, (LPCRITICAL_SECTION lpCriticalSection)) {
  *lpCriticalSection = {};
}

DLLEXPORT_FUNC(void, EnterCriticalSection, (LPCRITICAL_SECTION lpCriticalSection)) {
  HANDLE Self = CurrentThreadId();
  if (lpCriticalSection->OwningThread == Self) {
    ++lpCriticalSection->RecursionCount;
    return;
  }
  auto& State = CSWord(lpCriticalSection);
  uint32_t Cur = 0;
  if (!State.compare_exchange_strong(Cur, 1, std::memory_order_acquire, std::memory_order_relaxed)) {
    if (Cur != 2) {
      Cur = State.exchange(2, std::memory_order_acquire);
    }
    while (Cur) {
      uint32_t Contended = 2;
      ParkOnAddress(&State, &Contended, sizeof(Contended), nullptr);
      Cur = State.exchange(2, std::memory_order_acquire);
    }
  }
  lpCriticalSection->OwningThread = Self;
  lpCriticalSection->RecursionCount = 1;
}

DLLEXPORT_FUNC(void, LeaveCriticalSection, (LPCRITICAL_SECTION lpCriticalSection)) {
  if (--lpCriticalSection->RecursionCount) {
    return;
  }
  lpCriticalSection->OwningThread = nullptr;
  auto& State = CSWord(lpCriticalSection);
  if (State.exchange(0, std::memory_order_release) == 2) {
    UnparkAddress(&State, false);
  }
}

DLLEXPORT_FUNC(WINBOOL, TryEnterCriticalSection, (LPCRITICAL_SECTION lpCriticalSection)) {
  HANDLE Self = CurrentThreadId();
  if (lpCriticalSection->OwningThread == Self) {
    ++lpCriticalSection->RecursionCount;
    return TRUE;
  }
  uint32_t Cur = 0;
  if (!CSWord(lpCriticalSection).compare_exchange_strong(Cur, 1, std::memory_order_acquire, std::memory_order_relaxed)) {
    return FALSE;
  }
  lpCriticalSection->OwningThread = Self;
  lpCriticalSection->RecursionCount = 1;
  return TRUE;
}

DLLEXPORT_FUNC(void, DeleteCriticalSection, (LPCRITICAL_SECTION lpCriticalSection)) { }

DLLEXPORT_FUNC(void, InitializeConditionVariable, (PCONDITION_VARIABLE ConditionVariable)) {
  ConditionVariable->Ptr = nullptr;
}

// Condition variable: a wake sequence number in the low 32 bits.
DLLEXPORT_FUNC(void, WakeConditionVariable, (PCONDITION_VARIABLE ConditionVariable)) {
  auto& Seq = Word(ConditionVariable);
  Seq.fetch_add(1, std::memory_order_release);
  UnparkAddress(&Seq, false);
}

DLLEXPORT_FUNC(void, WakeAllConditionVariable, (PCONDITION_VARIABLE ConditionVariable)) {
  auto& Seq = Word(ConditionVariable);
  Seq.fetch_add(1, std::memory_order_release);
  UnparkAddress(&Seq, true);
}

DLLEXPORT_FUNC(WINBOOL, SleepConditionVariableSRW, (PCONDITION_VARIABLE ConditionVariable, PSRWLOCK SRWLock, DWORD dwMilliseconds, ULONG Flags)) {
  auto& Seq = Word(ConditionVariable);
  // Read the sequence while still holding the lock, so a wake that follows our unlock changes it and isn't missed.
  uint32_t Cur = Seq.load(std::memory_order_acquire);
  const bool Shared = Flags & CONDITION_VARIABLE_LOCKMODE_SHARED;
  Shared ? ReleaseSRWLockShared(SRWLock) : ReleaseSRWLockExclusive(SRWLock);
  LARGE_INTEGER Time;
  bool Woken = ParkOnAddress(&Seq, &Cur, sizeof(Cur), RelativeTimeout(dwMilliseconds, &Time));
  Shared ? AcquireSRWLockShared(SRWLock) : AcquireSRWLockExclusive(SRWLock);
  if (!Woken) {
    SetLastError(ERROR_TIMEOUT);
    return FALSE;
  }
  return TRUE;
}

DLLEXPORT_FUNC(WINBOOL, InitOnceExecuteOnce, (PINIT_ONCE InitOnce, PINIT_ONCE_FN InitFn, void* Parameter, void** Context)) {
  return !RtlRunOnceExecuteOnce(InitOnce, reinterpret_cast<PRTL_RUN_ONCE_INIT_FN>(InitFn), Parameter, Context);
}

DLLEXPORT_FUNC(DWORD, WaitForSingleObjectEx, (HANDLE hHandle, DWORD dwMilliseconds, WINBOOL bAlertable)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(HANDLE, GetProcessHeap, ()) {
  return GetCurrentPEB()->ProcessHeap;
}

DLLEXPORT_FUNC(DWORD, GetCurrentProcessId, ()) {
  return static_cast<DWORD>(reinterpret_cast<uintptr_t>(GetCurrentTEB()->ClientId.UniqueProcess));
}

DLLEXPORT_FUNC(DWORD, GetCurrentThreadId, ()) {
  return static_cast<DWORD>(reinterpret_cast<uintptr_t>(GetCurrentTEB()->ClientId.UniqueThread));
}

DLLEXPORT_FUNC(DWORD, GetThreadId, (HANDLE Thread)) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(HANDLE, GetCurrentProcess, ()) {
  return NtCurrentProcess();
}

DLLEXPORT_FUNC(HANDLE, GetCurrentThread, ()) {
  return NtCurrentThread();
}

DLLEXPORT_FUNC(DWORD, GetCurrentProcessorNumber, ()) {
  return NtGetCurrentProcessorNumber();
}

DLLEXPORT_FUNC(WINBOOL, SwitchToThread, ()) {
  UNIMPLEMENTED();
}

DLLEXPORT_FUNC(void, Sleep, (DWORD dwMilliseconds)) {
  LARGE_INTEGER Time;
  // A negative value indicates a relative time measured in 100ns intervals.
  Time.QuadPart = static_cast<ULONGLONG>(dwMilliseconds) * -10000;
  NtDelayExecution(false, &Time);
}
