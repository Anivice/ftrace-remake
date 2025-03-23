#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H

#include <map>
#include <string>
#include <vector>

class Arguments {
public:
    using args_t = std::map < std::string, std::vector < std::string > >;
    using sub_process_args_t = std::vector < std::string >;
    using sub_process_t = std::string;
    using sub_process_bundle_t = std::pair < sub_process_t, sub_process_args_t >;

private:
    args_t arguments;
    sub_process_bundle_t sub_process_bundle;

    void parse_ftrace_args_from_bundle(const std::vector<std::string> & args);

public:
    explicit Arguments(int argc, const char *argv[]);
    [[nodiscard]] explicit operator args_t() const {
        return this->arguments;
    }

    [[nodiscard]] explicit operator sub_process_bundle_t() const {
        return this->sub_process_bundle;
    }
};

#endif //ARGUMENT_PARSER_H
