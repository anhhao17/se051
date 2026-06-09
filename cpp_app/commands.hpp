/**
 * @file commands.hpp
 * @brief Registry of all CLI commands.
 *
 * Owns the concrete Command instances and indexes them by (group, name) so the
 * dispatcher and main() can look a command up, ask what session it needs, and
 * run it - without any command-specific knowledge of their own.
 */

#pragma once
#include "command.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/** @brief Holds and indexes every CLI command. */
class CommandRegistry {
public:
    CommandRegistry();

    /**
     * @brief Look up a command.
     * @return matching Command, or nullptr if none.  Falls back to a group's
     *         default command (name "") so positional forms like `rng 16` work.
     */
    const Command *find(const std::string &group, const std::string &command) const;

    /** @brief Print grouped usage to stderr. */
    void usage(const char *prog) const;

private:
    void add(std::unique_ptr<Command> c);

    std::vector<std::unique_ptr<Command>> cmds_;
    std::map<std::pair<std::string, std::string>, const Command *> index_;
};
