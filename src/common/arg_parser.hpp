// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WinQuicEcho contributors

#pragma once

#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace winquicecho {

class arg_parser {
  public:
    void add_option(const std::string& long_name, char short_name, const std::string& default_value,
                    bool takes_value, const std::string& description) {
        option opt{};
        opt.short_name = short_name;
        opt.default_value = default_value;
        opt.value = default_value;
        opt.takes_value = takes_value;
        opt.description = description;
        opts_.emplace(long_name, std::move(opt));
        if (short_name != '\0') {
            short_to_long_.emplace(short_name, long_name);
        }
    }

    void parse(int argc, const char* const argv[]) {
        for (int i = 1; i < argc; ++i) {
            const char* arg = argv[i];
            if (std::strncmp(arg, "--", 2) == 0) {
                parse_long_option(argc, argv, i, arg + 2);
            } else if (arg[0] == '-' && arg[1] != '\0') {
                parse_short_option(argc, argv, i, arg[1]);
            } else {
                positional_.emplace_back(arg);
            }
        }
    }

    std::string get(const std::string& long_name) const {
        const auto it = opts_.find(long_name);
        if (it == opts_.end()) {
            throw std::invalid_argument("Unknown option: " + long_name);
        }
        return it->second.value;
    }

    bool is_set(const std::string& long_name) const {
        const auto it = opts_.find(long_name);
        if (it == opts_.end()) {
            return false;
        }
        return it->second.explicitly_set;
    }

    void print_help(const char* program_name) const {
        std::cout << "Usage: " << program_name << " [options]\n";
        std::cout << "Options:\n";
        for (const auto& [name, opt] : opts_) {
            std::cout << "  --" << name;
            if (opt.short_name != '\0') {
                std::cout << ", -" << opt.short_name;
            }
            if (opt.takes_value) {
                std::cout << " <value>";
            }
            std::cout << "\n      default: " << opt.default_value;
            if (!opt.description.empty()) {
                std::cout << "\n      " << opt.description;
            }
            std::cout << "\n";
        }
    }

    const std::vector<std::string>& positional() const { return positional_; }

  private:
    struct option {
        char short_name{};
        std::string default_value;
        std::string value;
        bool takes_value{};
        bool explicitly_set{};
        std::string description;
    };

    void parse_long_option(int argc, const char* const argv[], int& index, const char* option_text) {
        const char* equals = std::strchr(option_text, '=');
        std::string key;
        std::string value;
        if (equals != nullptr) {
            key.assign(option_text, equals - option_text);
            value.assign(equals + 1);
        } else {
            key.assign(option_text);
        }

        const auto it = opts_.find(key);
        if (it == opts_.end()) {
            std::cerr << "Warning: unknown option '--" << key << "' (ignored)\n";
            return;
        }
        set_option_value(it->second, argc, argv, index, value);
    }

    void parse_short_option(int argc, const char* const argv[], int& index, char short_name) {
        const auto map_it = short_to_long_.find(short_name);
        if (map_it == short_to_long_.end()) {
            std::cerr << "Warning: unknown option '-" << short_name << "' (ignored)\n";
            return;
        }
        const auto opt_it = opts_.find(map_it->second);
        if (opt_it == opts_.end()) {
            return;
        }
        set_option_value(opt_it->second, argc, argv, index, "");
    }

    static void set_option_value(option& opt, int argc, const char* const argv[], int& index,
                                 const std::string& supplied_value) {
        if (!opt.takes_value) {
            opt.value = "1";
            opt.explicitly_set = true;
            return;
        }

        if (!supplied_value.empty()) {
            opt.value = supplied_value;
            opt.explicitly_set = true;
            return;
        }

        if (index + 1 < argc) {
            opt.value = argv[++index];
            opt.explicitly_set = true;
        }
    }

    std::map<std::string, option> opts_;
    std::map<char, std::string> short_to_long_;
    std::vector<std::string> positional_;
};

}  // namespace winquicecho
