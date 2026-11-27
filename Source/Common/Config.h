// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Config/Config.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/vector.h>

#include <string_view>

namespace FEX::ArgLoader {
class ArgLoader;
}
/**
 * @brief This is a singleton for storing global configuration state
 */
namespace FEX::Config {
class EmptyMapper : public FEXCore::Config::Layer {
public:
  explicit EmptyMapper()
    : FEXCore::Config::Layer(FEXCore::Config::LayerType::LAYER_MAIN) {}
  void Load() override {}

protected:
};

void SaveLayerToJSON(const fextl::string& Filename, const FEXCore::Config::Layer* Layer);
void SaveLayerToJSON(const fextl::string& Filename, const FEXCore::Config::Layer* Layer, const fextl::unordered_map<fextl::string, bool>& HostLibs);

struct ApplicationNames {
  // This is the full path to the program (if it exists).
  fextl::string ProgramPath;
  // This is the program executable name (if it exists).
  fextl::string ProgramName;
};

struct PortableInformation {
  bool IsPortable;
  // Path of folder containing FEX (including / at the end)
  fextl::string InterpreterPath;
};

/**
 * @param ExecFDInterp If FEX was executed with binfmt_misc FD argument
 * @param ProgramFDFromEnv The execveat FD argument passed through FEX
 *
 * @return The application name and path structure
 */
ApplicationNames GetApplicationNames(const fextl::vector<fextl::string>& Args, bool ExecFDInterp, int ProgramFDFromEnv);

/**
 * @brief Whether this process runs with credentials it was not started with.
 *
 * The kernel sets AT_SECURE when an exec changes credentials: a set-user-ID or set-group-ID
 * program, file capabilities, or a binfmt_misc handler registered with the C flag.
 */
bool IsSecureExecution();

/**
 * @brief Loads the FEX and application configurations for the application that is getting ready to run.
 *
 * @param ProgramName Optional program name, if non-empty application specific configurations will be loaded
 * @param envp Optional `envp` passed to main(...)
 * @param SecureExecution Load only the system's configuration: no user config, app override or FEX_* variable,
 * and only the system's directories, as the dynamic loader ignores LD_* variables under AT_SECURE.
 */
void LoadConfig(fextl::string ProgramName = {}, char** const envp = nullptr, const PortableInformation& PortableInfo = {},
                bool SecureExecution = IsSecureExecution());

/**
 * @brief The config files searched for a ThunksDB section, lowest priority first
 *
 * @param AppName The application's config name
 * @param ThunkConfigFile The ThunkConfig option's file
 */
fextl::vector<fextl::string> GetThunksDBConfigPaths(const fextl::string& AppName, const fextl::string& ThunkConfigFile);

fextl::string GetHomeDirectory();

fextl::string GetDataDirectory(bool Global, const PortableInformation& PortableInfo);
fextl::string GetConfigDirectory(bool Global, const PortableInformation& PortableInfo);
fextl::string GetConfigFileLocation(bool Global, const PortableInformation& PortableInfo);
fextl::string GetCacheDirectory();

void InitializeConfigs(const PortableInformation& PortableInfo);

/**
 * @brief Loads the global FEX config
 *
 * @return unique_ptr for that layer
 */
fextl::unique_ptr<FEXCore::Config::Layer> CreateGlobalMainLayer();

/**
 * @brief Loads the main application config
 *
 * @param File Optional override to load a specific config file in to the main layer
 * Shouldn't be commonly used
 *
 * @return unique_ptr for that layer
 */
fextl::unique_ptr<FEXCore::Config::Layer> CreateMainLayer(const fextl::string* File = nullptr, std::optional<fextl::string> AppName = std::nullopt);
fextl::unique_ptr<FEXCore::Config::Layer> CreateUserOverrideLayer(std::string_view AppConfig, std::optional<fextl::string> AppName);

/**
 * @brief Create an application configuration loader
 *
 * @param Filename Application filename component
 * @param Global Load the global configuration or user accessible file
 *
 * @return unique_ptr for that layer
 */
fextl::unique_ptr<FEXCore::Config::Layer> CreateAppLayer(const fextl::string& Filename, FEXCore::Config::LayerType Type);

/**
 * @brief iCreate an environment configuration loader
 *
 * @param _envp[] The environment array from main
 *
 * @return unique_ptr for that layer
 */
fextl::unique_ptr<FEXCore::Config::Layer> CreateEnvironmentLayer(char* const _envp[]);
} // namespace FEX::Config
