#include "vpn/trusttunnel/subscription_refresh.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include "trusttunnel_subscription.h"
#include "vpn/platform.h"

namespace ag {

using FfiString = std::unique_ptr<char, decltype(&trusttunnel_subscription_string_free)>;

#ifdef _WIN32
/**
 * Convert a UTF-8 path to the wide form the Windows file APIs expect.
 * Return an empty string when the path is not valid UTF-8.
 */
static std::wstring widen_path(std::string_view path) {
    if (path.empty()) {
        return {};
    }

    std::wstring wide;
    int len =
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), nullptr, 0);
    if (len != 0) {
        wide.resize(static_cast<size_t>(len));
        MultiByteToWideChar(
                CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), wide.data(), len);
    }
    return wide;
}
#endif

/**
 * Read the whole file at `path`. On failure return an empty optional and
 * set `detail` to the OS error message.
 */
static std::optional<std::string> read_text_file(const std::string &path, std::string &detail) {
    errno = 0;
#ifdef _WIN32
    std::wstring wide_path = widen_path(path);
    if (wide_path.empty()) {
        detail = "Path is not valid UTF-8";
        return std::nullopt;
    }
    std::ifstream stream(wide_path.c_str(), std::ios::binary);
#else
    std::ifstream stream(path, std::ios::binary);
#endif
    std::ostringstream content;
    if (stream) {
        content << stream.rdbuf();
    }
    if (!stream) {
        detail = std::strerror(errno);
        return std::nullopt;
    }
    return content.str();
}

/**
 * Print the diagnostic carried by `error` (a fallback when absent) and free it.
 */
static void print_and_free_error(SubscriptionFfiError *error) {
    const char *message = (error != nullptr) ? trusttunnel_subscription_error_message(error) : "unknown error";
    std::fprintf(stderr, "Refresh failed: %s\n", message);
    trusttunnel_subscription_error_free(error);
}

int run_subscription_refresh(const std::string &config_path) {
    std::string detail;
    std::optional<std::string> config_text = read_text_file(config_path, detail);
    if (!config_text) {
        std::fprintf(stderr, "Refresh failed: Cannot read config file '%s': %s\n", config_path.c_str(), detail.c_str());
        return 1;
    }

    SubscriptionFfiError *error = nullptr;
    char *json_raw = nullptr;
    if (trusttunnel_subscription_fetch_for_config(config_text->c_str(), &json_raw, &error) != 0) {
        print_and_free_error(error);
        return 1;
    }
    FfiString json(json_raw, &trusttunnel_subscription_string_free);

    char *updated_raw = nullptr;
    if (trusttunnel_subscription_apply(config_text->c_str(), json.get(), &updated_raw, &error) != 0) {
        print_and_free_error(error);
        return 1;
    }
    FfiString updated(updated_raw, &trusttunnel_subscription_string_free);

    if (trusttunnel_subscription_replace_file_atomic(config_path.c_str(), updated.get(), &error) != 0) {
        print_and_free_error(error);
        return 1;
    }

    std::fprintf(stderr, "Configuration refreshed from the subscription URL\n");
    return 0;
}

} // namespace ag
