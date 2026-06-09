/**
 * @file cli.cpp
 * @brief Argument parsing implementation.
 */

#include "cli.hpp"

#include <string>
#include <vector>

namespace {
// Flags that do not take a value.
bool isBoolFlag(const std::string &t) {
    return t == "--force" || t == "--dry-run" || t == "--confirm" || t == "--pem" ||
           t == "--rewritable" || t == "--debug" || t == "--verbose";
}
} // namespace

Args parseArgs(int argc, char **argv) {
    Args                     a;
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string t = argv[i];
        if (t.rfind("--", 0) == 0) {
            if (isBoolFlag(t)) {
                a.opt[t] = "1";
            } else if (i + 1 < argc) {
                a.opt[t] = argv[++i];
            } else {
                a.opt[t] = "1";
            }
        } else {
            pos.push_back(t);
        }
    }
    if (pos.size() > 0) a.group = pos[0];
    if (pos.size() > 1) a.command = pos[1];
    if (pos.size() > 2) a.positional = pos[2];
    if (a.group == "rng" && a.positional.empty()) a.positional = a.command;
    return a;
}
