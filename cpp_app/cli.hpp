/**
 * @file cli.hpp
 * @brief Command-line argument parsing.
 *
 * Single responsibility: turn argv into a structured Args.  Dispatch lives in
 * the CommandRegistry; session setup lives in main().
 */

#pragma once
#include "command.hpp" // Args

/**
 * @brief Parse argv into Args (positional group/command/positional + --opt map).
 *
 * Value-less flags (--force, --dry-run, --confirm, --pem) are recorded as set
 * without consuming the next token; every other --opt takes the following token
 * as its value.
 */
Args parseArgs(int argc, char **argv);
