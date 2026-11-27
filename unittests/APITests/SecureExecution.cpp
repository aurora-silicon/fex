// SPDX-License-Identifier: MIT
#include "Common/Config.h"
#include "Common/FEXServerClient.h"
#include "Common/InheritedFDs.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <linux/limits.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace {
// A home directory with the user's own Config.json, and an app config override beside it.
struct UserConfigs {
  std::filesystem::path Root;

  UserConfigs() {
    char Template[] = "/tmp/fex-secure-execution-XXXXXX";
    Root = mkdtemp(Template);
    std::filesystem::create_directories(Root / ".fex-emu");
    WriteRootFS(Root / ".fex-emu/Config.json", "/user/rootfs");
    WriteRootFS(Root / "override.json", "/override/rootfs");
    setenv("HOME", Root.c_str(), 1);
    for (const char* Name :
         {"XDG_CONFIG_HOME", "XDG_DATA_HOME", "FEX_APP_CONFIG_LOCATION", "FEX_APP_DATA_LOCATION", "FEX_APP_CONFIG", "SteamAppId"}) {
      unsetenv(Name);
    }
  }

  ~UserConfigs() {
    unsetenv("FEX_APP_CONFIG");
    unsetenv("SteamAppId");
    std::filesystem::remove_all(Root);
  }

  static void WriteRootFS(const std::filesystem::path& Path, const char* RootFS) {
    std::ofstream(Path) << "{\"Config\": {\"RootFS\": \"" << RootFS << "\"}}\n";
  }
};

// Runs with the working directory the caller chose.
struct WorkingDirectory {
  std::filesystem::path Previous;

  explicit WorkingDirectory(const std::filesystem::path& Path)
    : Previous {std::filesystem::current_path()} {
    std::filesystem::current_path(Path);
  }

  ~WorkingDirectory() {
    std::filesystem::current_path(Previous);
  }
};

// Stands in for values from the system's config, which a test can't write.
class SystemValues final : public FEXCore::Config::Layer {
public:
  SystemValues()
    : FEXCore::Config::Layer(FEXCore::Config::LayerType::LAYER_ARGUMENTS) {}

  void Load() override {}
};

using SystemLayer = fextl::unique_ptr<SystemValues>;

// Loads the config the way FEXInterpreter does, with SystemValues on top, and reads it with Read().
template<typename ReadFn>
auto WithConfig(bool SecureExecution, SystemLayer System, ReadFn&& Read, char** Envp = nullptr) {
  char* WithoutVariables[] = {nullptr};
  FEX::Config::LoadConfig("secure-execution-test", Envp ? Envp : WithoutVariables, {}, SecureExecution);
  if (System) {
    FEXCore::Config::AddLayer(std::move(System));
  }
  FEXCore::Config::ReloadMetaLayer();
  auto Result = Read();
  FEXCore::Config::Shutdown();
  return Result;
}

fextl::string GetString(FEXCore::Config::ConfigOption Option) {
  auto Value = FEXCore::Config::Get(Option);
  return Value ? **Value : fextl::string {};
}

bool GetBool(FEXCore::Config::ConfigOption Option) {
  return FEXCore::Config::GetConv<bool>(Option).value_or(false);
}

struct Loaded {
  fextl::string RootFS;
  fextl::string ConfigDirectory;
  fextl::string DataDirectory;
};

Loaded Load(bool SecureExecution, char** Envp) {
  return WithConfig(
    SecureExecution, nullptr,
    [] {
      return Loaded {GetString(FEXCore::Config::CONFIG_ROOTFS), FEXCore::Config::GetConfigDirectory(false),
                     FEXCore::Config::GetDataDirectory(false)};
    },
    Envp);
}

// A FEXServer the caller runs on the socket name FEX connects to. It answers the RootFS request with a
// directory the caller controls.
class CallerServer {
public:
  static constexpr const char* RootFS = "/caller/rootfs";

  CallerServer() {
    Listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(Listener != -1);
    REQUIRE(pipe2(Stop, O_CLOEXEC) == 0);

    // The abstract name FEXServerClient::ConnectToServer() tries first. If this user's own FEXServer
    // already holds it, FEX would reach that server instead, which is just as much the caller's.
    const auto Name = fextl::fmt::format("{}.FEXServer.Socket", getuid());
    sockaddr_un Addr {.sun_family = AF_UNIX};
    memcpy(Addr.sun_path + 1, Name.data(), Name.size());
    Bound = bind(Listener, reinterpret_cast<sockaddr*>(&Addr), sizeof(Addr.sun_family) + 1 + Name.size()) == 0 && listen(Listener, 4) == 0;

    Thread = std::thread([this] { Serve(); });
  }

  ~CallerServer() {
    const char Byte {};
    (void)write(Stop[1], &Byte, 1);
    Thread.join();
    close(Listener);
    close(Stop[0]);
    close(Stop[1]);
  }

  bool Bound {};
  std::atomic<int> Connections {};

private:
  void Serve() {
    pollfd Fds[2] = {{.fd = Listener, .events = POLLIN}, {.fd = Stop[0], .events = POLLIN}};
    while (poll(Fds, 2, -1) > 0 && !Fds[1].revents) {
      if (!(Fds[0].revents & POLLIN)) {
        continue;
      }
      int Client = accept4(Listener, nullptr, nullptr, SOCK_CLOEXEC);
      if (Client == -1) {
        continue;
      }
      ++Connections;

      FEXServerClient::FEXServerRequestPacket Req {};
      if (recv(Client, &Req, sizeof(Req.BasicRequest), 0) == sizeof(Req.BasicRequest) &&
          Req.Header.Type == FEXServerClient::PacketType::TYPE_GET_ROOTFS_PATH) {
        alignas(FEXServerClient::FEXServerResultPacket) char Buffer[sizeof(FEXServerClient::FEXServerResultPacket) + PATH_MAX] {};
        auto* Res = reinterpret_cast<FEXServerClient::FEXServerResultPacket*>(Buffer);
        Res->MountPath.Header.Type = FEXServerClient::PacketType::TYPE_GET_ROOTFS_PATH;
        Res->MountPath.Length = strlen(RootFS) + 1;
        memcpy(Res->MountPath.Mount, RootFS, Res->MountPath.Length);
        (void)send(Client, Buffer, sizeof(FEXServerClient::FEXServerResultPacket) + Res->MountPath.Length, MSG_NOSIGNAL);
      }
      close(Client);
    }
  }

  int Listener {-1};
  int Stop[2] {-1, -1};
  std::thread Thread;
};
} // namespace

TEST_CASE("SecureExecution - only the system's configuration") {
  UserConfigs User;
  char EnvironmentRootFS[] = "FEX_ROOTFS=/environment/rootfs";
  char* WithVariable[] = {EnvironmentRootFS, nullptr};
  char* WithoutVariables[] = {nullptr};

  // Normally the user's config, an app config override and FEX_* variables apply, each over the last.
  CHECK(Load(false, WithoutVariables).RootFS == "/user/rootfs");
  setenv("FEX_APP_CONFIG", (User.Root / "override.json").c_str(), 1);
  CHECK(Load(false, WithoutVariables).RootFS == "/override/rootfs");
  CHECK(Load(false, WithVariable).RootFS == "/environment/rootfs");

  // With credentials the caller did not have, none of them does, and FEX's directories are the system's.
  const auto Secure = Load(true, WithVariable);
  CHECK(Secure.RootFS != "/user/rootfs");
  CHECK(Secure.RootFS != "/override/rootfs");
  CHECK(Secure.RootFS != "/environment/rootfs");
  CHECK(Secure.ConfigDirectory == GLOBAL_DATA_DIRECTORY);
  CHECK(Secure.DataDirectory == GLOBAL_DATA_DIRECTORY);
}

TEST_CASE("SecureExecution - relative paths don't resolve in the caller's directories") {
  UserConfigs User;

  // The system config names its paths relatively; the caller's working directory and HOME hold entries
  // with those names.
  const auto Work = User.Root / "work";
  std::filesystem::create_directories(Work / "secure-execution-test-rootfs");
  std::filesystem::create_directories(Work / "secure-execution-test-host-thunks");
  std::filesystem::create_directories(User.Root / "secure-execution-test-guest-thunks");
  std::ofstream(Work / "secure-execution-test-thunks.json") << "{}\n";
  std::ofstream(Work / "secure-execution-test.log") << "\n";
  WorkingDirectory InWork {Work};

  auto System = [] {
    auto Layer = fextl::make_unique<SystemValues>();
    Layer->Set(FEXCore::Config::CONFIG_ROOTFS, "secure-execution-test-rootfs");
    Layer->Set(FEXCore::Config::CONFIG_THUNKHOSTLIBS, "secure-execution-test-host-thunks");
    Layer->Set(FEXCore::Config::CONFIG_THUNKGUESTLIBS, "~/secure-execution-test-guest-thunks");
    Layer->Set(FEXCore::Config::CONFIG_THUNKCONFIG, "secure-execution-test-thunks.json");
    Layer->Set(FEXCore::Config::CONFIG_OUTPUTLOG, "secure-execution-test.log");
    return Layer;
  };

  struct Paths {
    fextl::string RootFS, HostThunks, GuestThunks, ThunkConfig, OutputLog;
  };
  auto Read = [] {
    return Paths {
      GetString(FEXCore::Config::CONFIG_ROOTFS),         GetString(FEXCore::Config::CONFIG_THUNKHOSTLIBS),
      GetString(FEXCore::Config::CONFIG_THUNKGUESTLIBS), GetString(FEXCore::Config::CONFIG_THUNKCONFIG),
      GetString(FEXCore::Config::CONFIG_OUTPUTLOG),
    };
  };

  // Normally a relative path resolves against the working directory, and ~/ against HOME.
  const auto Normal = WithConfig(false, System(), Read);
  const auto Is = [](const fextl::string& Path, const std::filesystem::path& Expected) {
    return !Path.empty() && std::filesystem::exists(Path.c_str()) && std::filesystem::equivalent(Path.c_str(), Expected);
  };
  CHECK(Is(Normal.RootFS, Work / "secure-execution-test-rootfs"));
  CHECK(Is(Normal.HostThunks, Work / "secure-execution-test-host-thunks"));
  CHECK(Is(Normal.GuestThunks, User.Root / "secure-execution-test-guest-thunks"));
  CHECK(Is(Normal.ThunkConfig, Work / "secure-execution-test-thunks.json"));
  CHECK(Is(Normal.OutputLog, Work / "secure-execution-test.log"));

  // With credentials the caller did not have, they resolve only under the system's directories. These
  // names exist in none of them, so the paths are dropped rather than opened in the caller's directories.
  const auto Secure = WithConfig(true, System(), Read);
  CHECK(Secure.RootFS.empty());
  CHECK(Secure.HostThunks.empty());
  CHECK(Secure.GuestThunks.empty());
  CHECK(Secure.ThunkConfig.empty());
  CHECK(Secure.OutputLog.empty());

  // Absolute paths and the named log outputs stay as the system config wrote them.
  auto Absolute = [] {
    auto Layer = fextl::make_unique<SystemValues>();
    Layer->Set(FEXCore::Config::CONFIG_ROOTFS, "/system/rootfs");
    Layer->Set(FEXCore::Config::CONFIG_OUTPUTLOG, "stderr");
    return Layer;
  };
  const auto SecureAbsolute = WithConfig(true, Absolute(), Read);
  CHECK(SecureAbsolute.RootFS == "/system/rootfs");
  CHECK(SecureAbsolute.OutputLog == "stderr");
}

TEST_CASE("SecureExecution - no FEXServer chooses the RootFS") {
  UserConfigs User;
  CallerServer Server;

  auto System = [] {
    auto Layer = fextl::make_unique<SystemValues>();
    Layer->Set(FEXCore::Config::CONFIG_ROOTFS, "/system/rootfs");
    return Layer;
  };
  struct Client {
    bool SetUp;
    int ServerFD;
    fextl::string RootFS;
  };
  auto Connect = [] {
    const bool SetUp = FEXServerClient::SetupClient("/nonexistent/FEX");
    return Client {SetUp, FEXServerClient::GetServerFD(), GetString(FEXCore::Config::CONFIG_ROOTFS)};
  };

  // With credentials the caller did not have, FEX doesn't connect, and the system config's RootFS stays.
  const auto Secure = WithConfig(true, System(), Connect);
  CHECK_FALSE(Secure.SetUp);
  CHECK(Secure.ServerFD == -1);
  CHECK(Secure.RootFS == "/system/rootfs");
  CHECK(Server.Connections == 0);

  // Normally the server's RootFS replaces it, which is what the check above guards against.
  if (Server.Bound) {
    const auto Normal = WithConfig(false, System(), Connect);
    CHECK(Normal.SetUp);
    CHECK(Normal.RootFS == CallerServer::RootFS);
    CHECK(Server.Connections == 1);
  }
}

TEST_CASE("SecureExecution - the thunk database reads only the system's configs") {
  UserConfigs User;
  setenv("SteamAppId", "1234", 1);
  setenv("FEX_APP_CONFIG", "/caller/override.json", 1);

  auto Read = [] {
    return FEX::Config::GetThunksDBConfigPaths("secure-execution-test", "");
  };
  auto Has = [](const fextl::vector<fextl::string>& Paths, std::string_view Part) {
    return std::any_of(Paths.begin(), Paths.end(), [&](const auto& Path) { return Path.find(Part) != Path.npos; });
  };

  // Normally FEX_APP_CONFIG and the Steam app configs apply.
  const auto Normal = WithConfig(false, nullptr, Read);
  CHECK(Has(Normal, "/caller/override.json"));
  CHECK(Has(Normal, "Steam_1234_"));

  // With credentials the caller did not have, neither does, and every config is under the system's directory.
  const auto Secure = WithConfig(true, nullptr, Read);
  CHECK_FALSE(Has(Secure, "/caller/override.json"));
  CHECK_FALSE(Has(Secure, "Steam_1234_"));
  for (const auto& Path : Secure) {
    CHECK((Path.empty() || Path.starts_with(GLOBAL_DATA_DIRECTORY)));
  }
}

TEST_CASE("SecureExecution - no code caches or telemetry") {
  auto System = [] {
    auto Layer = fextl::make_unique<SystemValues>();
    Layer->Set(FEXCore::Config::CONFIG_ENABLECODECACHINGWIP, "1");
    Layer->Set(FEXCore::Config::CONFIG_DISKCACHE, "1");
    Layer->Set(FEXCore::Config::CONFIG_DISABLETELEMETRY, "0");
    return Layer;
  };
  struct Options {
    bool CodeCaching, DiskCache, DisableTelemetry;
  };
  auto Read = [] {
    return Options {GetBool(FEXCore::Config::CONFIG_ENABLECODECACHINGWIP), GetBool(FEXCore::Config::CONFIG_DISKCACHE),
                    GetBool(FEXCore::Config::CONFIG_DISABLETELEMETRY)};
  };

  const auto Normal = WithConfig(false, System(), Read);
  CHECK(Normal.CodeCaching);
  CHECK(Normal.DiskCache);
  CHECK_FALSE(Normal.DisableTelemetry);

  const auto Secure = WithConfig(true, System(), Read);
  CHECK_FALSE(Secure.CodeCaching);
  CHECK_FALSE(Secure.DiskCache);
  CHECK(Secure.DisableTelemetry);
}

TEST_CASE("SecureExecution - no fds from the environment") {
  auto SetAll = [] {
    setenv("FEX_EXECVEFD", "5", 1);
    setenv("FEX_EXECVEFD_PATH", "1", 1);
    setenv("FEX_SECCOMPFD", "6", 1);
  };
  auto NoneLeft = [] {
    return !getenv("FEX_EXECVEFD") && !getenv("FEX_EXECVEFD_PATH") && !getenv("FEX_SECCOMPFD");
  };

  // Normally FEX takes the program and the seccomp filters a parent FEX passed.
  SetAll();
  const auto Normal = FEX::TakeInheritedFDs(false);
  CHECK(Normal.ExecveFD == 5);
  CHECK(Normal.ExecveFDPathBacked);
  CHECK(Normal.SeccompFD == 6);
  CHECK_FALSE(Normal.SeccompRefused);
  CHECK(NoneLeft());

  // With credentials the caller did not have, it uses neither, and seccomp filters refuse the start.
  SetAll();
  const auto Secure = FEX::TakeInheritedFDs(true);
  CHECK(Secure.ExecveFD == -1);
  CHECK_FALSE(Secure.ExecveFDPathBacked);
  CHECK(Secure.SeccompFD == -1);
  CHECK(Secure.SeccompRefused);
  CHECK(NoneLeft());

  // Without FEX_SECCOMPFD it starts, still ignoring FEX_EXECVEFD.
  setenv("FEX_EXECVEFD", "5", 1);
  const auto SecureWithoutSeccomp = FEX::TakeInheritedFDs(true);
  CHECK(SecureWithoutSeccomp.ExecveFD == -1);
  CHECK(SecureWithoutSeccomp.SeccompFD == -1);
  CHECK_FALSE(SecureWithoutSeccomp.SeccompRefused);
  CHECK(NoneLeft());
}

TEST_CASE("SecureExecution - not for a process with its own credentials") {
  CHECK_FALSE(FEX::Config::IsSecureExecution());
}
