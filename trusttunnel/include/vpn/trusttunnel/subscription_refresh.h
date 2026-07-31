#pragma once

#include <string>

namespace ag {

/**
 * Refresh the live endpoint parameters of the config file from its
 * subscription URL: fetch the subscription document, merge it into the
 * config text and replace the file atomically. Print a human-readable
 * diagnostic on failure. Does not start the tunnel, open a listener, or
 * modify system routing.
 * @param config_path path to the config file (from --config), UTF-8
 *        encoded; on Windows it is converted to UTF-16 before opening,
 *        like toml::parse_file does.
 * @return process exit code: 0 on success, 1 on any failure.
 */
int run_subscription_refresh(const std::string &config_path);

} // namespace ag
