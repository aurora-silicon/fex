// SPDX-License-Identifier: MIT
/*
$info$
tags: glue|thunks
$end_info$
*/

#pragma once

namespace FEXCore::IR {
struct SHA256Sum;
}

namespace FEXCore {
typedef void ThunkedFunction(void* ArgsRv);

class ThunkHandler {
public:
  virtual ~ThunkHandler() = default;
  virtual ThunkedFunction* LookupThunk(const IR::SHA256Sum& sha256) = 0;

  /// Returns true if the thunk is a non-blocking leaf function guaranteed never to touch
  /// host FP/SIMD registers or FPCR (e.g., Linux ARM64 kernel vDSO timekeeping helpers).
  virtual bool IsNoFPLeafThunk(const IR::SHA256Sum& sha256) {
    return false;
  }
};
} // namespace FEXCore
