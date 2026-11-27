// SPDX-License-Identifier: MIT
#pragma once

#include <charconv>
#include <cstdlib>
#include <string_view>

namespace FEX {
/**
 * @brief The fds a parent FEX passes to the FEX it execs, through the environment.
 */
struct InheritedFDs {
  // FEX_EXECVEFD: the program to run.
  int ExecveFD {-1};
  // FEX_EXECVEFD_PATH: ExecveFD was opened from a path, rather than being an anonymous memfd.
  bool ExecveFDPathBacked {};
  // FEX_SECCOMPFD: the guest's seccomp filters, serialized as the host code that runs them.
  int SeccompFD {-1};
  // FEX_SECCOMPFD was set while running with credentials the caller did not have. FEX must not start.
  bool SeccompRefused {};
};

/**
 * @brief Get an FD from an environment variable and then unset the environment variable.
 *
 * @param Env The environment variable to extract the FD from.
 *
 * @return -1 if the variable didn't exist.
 */
inline int StealFEXFDFromEnv(const char* Env) {
  int FEXFD {-1};
  const char* FEXFDStr = getenv(Env);
  if (FEXFDStr) {
    const std::string_view FEXFDView {FEXFDStr};
    std::from_chars(FEXFDView.data(), FEXFDView.data() + FEXFDView.size(), FEXFD, 10);
    unsetenv(Env);
  }
  return FEXFD;
}

/**
 * @brief Takes the fds a parent FEX passed out of the environment.
 *
 * All of the variables leave the environment. With credentials the caller did not have, none of the fds is used, since
 * any caller can set the variables: the program comes from the arguments and AT_EXECFD only, and the seccomp filters
 * would be host code run with those credentials. Running without the filters would drop them instead, so a set
 * FEX_SECCOMPFD refuses the start.
 *
 * @param SecureExecution FEX runs with credentials the caller did not have.
 */
inline InheritedFDs TakeInheritedFDs(bool SecureExecution) {
  const bool HasSeccompFD = getenv("FEX_SECCOMPFD") != nullptr;
  InheritedFDs FDs {
    .ExecveFD = StealFEXFDFromEnv("FEX_EXECVEFD"),
    .ExecveFDPathBacked = getenv("FEX_EXECVEFD_PATH") != nullptr,
    .SeccompFD = StealFEXFDFromEnv("FEX_SECCOMPFD"),
  };
  unsetenv("FEX_EXECVEFD_PATH");

  if (SecureExecution) {
    FDs = InheritedFDs {
      .SeccompRefused = HasSeccompFD,
    };
  }
  return FDs;
}
} // namespace FEX
