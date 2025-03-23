#include "argument_parser.h"
#include <stdexcept>
#include <ios>
#include <sstream>

void replace_all(
    std::string & original,
    const std::string & target,
    const std::string & replacement)
{
    if (target.empty()) return; // Avoid infinite loop if target is empty

    // erase single character
    if (target.size() == 1 && replacement.empty()) {
        std::erase_if(original, [&](const char c) { return c == target[0]; });
    }

    size_t pos = 0;
    while ((pos = original.find(target, pos)) != std::string::npos) {
        original.replace(pos, target.length(), replacement);
        pos += replacement.length(); // Move past the replacement to avoid infinite loop
    }
}

std::vector<std::string> splitString(const std::string& input, const char delimiter = ',')
{
    std::vector<std::string> result;
    std::stringstream ss(input);
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }

    return result;
}

// arguments for frace is passed by -[char]=[value] or --[key]=[value], no space is allowed
// arguments for frace terminated by an arguments starts without '-' or end of argc
Arguments::Arguments(const int argc, const char *argv[])
{
    std::vector<std::string> ftrace_args;
    sub_process_t cmd_name;
    sub_process_args_t cmd_args;
    bool ftrace_args_exist = true;

    for (int i = 1; i < argc; ++i)
    {
        if (argv[i] == nullptr) {
            throw std::invalid_argument("NULL terminated before processing all arguments");
        }

        if (ftrace_args_exist)
        {
            if (argv[i][0] == '-') {
                ftrace_args.emplace_back(argv[i]);
            } else {
                ftrace_args_exist = false;
                cmd_name = argv[i];
            }
        } else {
            cmd_args.emplace_back(argv[i]);
        }
    }

    parse_ftrace_args_from_bundle(ftrace_args);
    sub_process_bundle = std::make_pair(cmd_name, cmd_args);
}

void Arguments::parse_ftrace_args_from_bundle(const std::vector<std::string> & args)
{
    for (const auto & arg : args)
    {
        std::string arg_str = arg;
        std::string f_arg;
        std::vector < std::string > f_val;
        replace_all(arg_str, "-", "");
        const auto keys = splitString(arg_str, '=');
        if (keys.empty()) {
            throw std::invalid_argument("Empty argument key provided");
        }

        f_arg = keys[0];

        if (keys.size() > 2) {
            throw std::invalid_argument("Argument key provided too long");
        }

        if (keys.size() == 2 && keys[1].contains(',')) {
            const std::string& key_val = keys[1];
            for (const auto vals = splitString(key_val, ',');
                const auto & val : vals)
            {
                f_val.emplace_back(val);
            }
        }

        if (arguments.contains(f_arg) /* key present */) {
            auto && list = arguments.at(f_arg);
            list.insert(list.end(), f_val.begin(), f_val.end()); // add keys
        } else { // key not present
            arguments.emplace(f_arg, f_val); // add entry
        }
    }
}
