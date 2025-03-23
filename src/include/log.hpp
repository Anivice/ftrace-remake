#ifndef LOG_HPP
#define LOG_HPP

#include <iostream>
#include <mutex>
#include <map>
#include <unordered_map>
#include <atomic>

#define construct_simple_type_compare(type)                             \
    template <typename T>                                               \
    struct is_##type : std::false_type {};                              \
    template <>                                                         \
    struct is_##type<type> : std::true_type { };                        \
    template <typename T>                                               \
    constexpr bool is_##type##_v = is_##type<T>::value;

#ifdef __HARDLINK_LOG__
# ifndef __LOG_TO_STDOUT__
#  define LOG_DEV std::cerr
#  define LOG_DEV_FILE (stderr)
# else // __LOG_TO_STDOUT__
#  define LOG_DEV std::cout
#  define LOG_DEV_FILE (stdout)
# endif // __LOG_TO_STDOUT__
#else // __HARDLINK_LOG__
namespace debug {
    extern std::atomic < decltype(std::cout) * > LOG_DEV_ptr;
# define LOG_DEV (*LOG_DEV_ptr)
    extern std::atomic < FILE * > LOG_DEV_FILE;
    void init_as_stdout();
    void init_as_stderr();
}
#endif // __HARDLINK_LOG__

namespace debug {
    template <typename T, typename = void>
    struct is_container : std::false_type
    {
    };

    template <typename T>
    struct is_container<T,
        std::void_t<decltype(std::begin(std::declval<T>())),
        decltype(std::end(std::declval<T>()))>> : std::true_type
    {
    };

    template <typename T>
    constexpr bool is_container_v = is_container<T>::value;

    template <typename T>
    struct is_map : std::false_type
    {
    };

    template <typename Key, typename Value>
    struct is_map<std::map<Key, Value>> : std::true_type
    {
    };

    template <typename T>
    constexpr bool is_map_v = is_map<T>::value;

    template <typename T>
    struct is_unordered_map : std::false_type
    {
    };

    template <typename Key, typename Value, typename Hash, typename KeyEqual,
        typename Allocator>
    struct is_unordered_map<
        std::unordered_map<Key, Value, Hash, KeyEqual, Allocator>>
        : std::true_type
    {
    };

    template <typename T>
    constexpr bool is_unordered_map_v = is_unordered_map<T>::value;

    template <typename T>
    struct is_string : std::false_type
    {
    };

    template <>
    struct is_string<std::basic_string<char>> : std::true_type
    {
    };

    template <>
    struct is_string<const char*> : std::true_type
    {
    };

    template <typename T>
    constexpr bool is_string_v = is_string<T>::value;

    construct_simple_type_compare(bool);

    inline class lower_case_bool_t {} lower_case_bool;
    construct_simple_type_compare(lower_case_bool_t);

    inline class upper_case_bool_t {} upper_case_bool;
    construct_simple_type_compare(upper_case_bool_t);

    inline class debug_log_t {} debug_log;
    construct_simple_type_compare(debug_log_t);

    inline class info_log_t {} info_log;
    construct_simple_type_compare(info_log_t);

    inline class warning_log_t {} warning_log;
    construct_simple_type_compare(warning_log_t);

    inline class error_log_t {} error_log;
    construct_simple_type_compare(error_log_t);

    template <typename T>
    struct is_pair : std::false_type
    {
    };

    template <typename Key, typename Value>
    struct is_pair<std::pair<Key, Value>> : std::true_type
    {
    };

    template <typename T>
    constexpr bool is_pair_v = is_pair<T>::value;

    template <typename Container>
    std::enable_if_t<is_container_v<Container> && !is_map_v<Container>
        && !is_unordered_map_v<Container>,
        void>
        print_container(const Container& container);

    template <typename Map>
    std::enable_if_t<is_map_v<Map> || is_unordered_map_v<Map>, void>
        print_container(const Map& map);

    extern std::mutex log_mutex;
    template <typename ParamType>
    void _log(const ParamType& param);
    template <typename ParamType, typename... Args>
    void _log(const ParamType& param, const Args&... args);

    /////////////////////////////////////////////////////////////////////////////////////////////

    template <typename... Args> void log(const Args&... args);

    template <typename Container>
    std::enable_if_t < debug::is_container_v<Container>
        && !debug::is_map_v<Container>
        && !debug::is_unordered_map_v<Container>
        , void >
        print_container(const Container& container)
    {
        LOG_DEV << "[";
        for (auto it = std::begin(container); it != std::end(container); ++it)
        {
            _log(*it);
            if (std::next(it) != std::end(container)) {
                LOG_DEV << ", ";
            }
        }
        LOG_DEV << "]";
    }

    template <typename Map>
    std::enable_if_t < debug::is_map_v<Map> || debug::is_unordered_map_v<Map>, void >
        print_container(const Map& map)
    {
        LOG_DEV << "{";
        for (auto it = std::begin(map); it != std::end(map); ++it)
        {
            _log(it->first);
            LOG_DEV << ": ";
            _log(it->second);
            if (std::next(it) != std::end(map)) {
                LOG_DEV << ", ";
            }
        }
        LOG_DEV << "}";
    }

    extern std::string str_true;
    extern std::string str_false;
    enum log_level_t { DEBUG = 0, INFO, WARNING, ERROR };
    extern std::atomic < log_level_t > log_level;
    extern std::atomic < log_level_t > current_level;

    template <typename ParamType> void _log(const ParamType& param)
    {
        auto level_check = [&]()->bool {
            return current_level >= log_level;
        };

        if constexpr (debug::is_string_v<ParamType>) {
            if (level_check()) {
                LOG_DEV << param;
            }
        }
        else if constexpr (debug::is_container_v<ParamType>) {
            if (level_check()) {
                debug::print_container(param);
            }
        }
        else if constexpr (debug::is_bool_v<ParamType>) {
            if (level_check()) {
                LOG_DEV << (param ? str_true : str_false);
            }
        }
        else if constexpr (debug::is_lower_case_bool_t_v<ParamType>) {
            str_true = "true";
            str_false = "false";
        }
        else if constexpr (debug::is_upper_case_bool_t_v<ParamType>) {
            str_true = "True";
            str_false = "False";
        }
        else if constexpr (debug::is_debug_log_t_v<ParamType>) {
            current_level = DEBUG;

            if (level_check()) {
                LOG_DEV << "[DEBUG] ";
            }
        }
        else if constexpr (debug::is_info_log_t_v<ParamType>) {
            current_level = INFO;

            if (level_check()) {
                LOG_DEV << "[INFO] ";
            }
        }
        else if constexpr (debug::is_warning_log_t_v<ParamType>) {
            current_level = WARNING;

            if (level_check()) {
                LOG_DEV << "[WARNING] ";
            }
        }
        else if constexpr (debug::is_error_log_t_v<ParamType>) {
            current_level = ERROR;

            if (level_check()) {
                LOG_DEV << "[ERROR] ";
            }
        }
        else if constexpr (debug::is_pair_v<ParamType>) {
            if (level_check()) {
                LOG_DEV << "<";
                _log(param.first);
                LOG_DEV << ": ";
                _log(param.second);
                LOG_DEV << ">";
            }
        }
        else {
            if (level_check()) {
                LOG_DEV << param;
            }
        }
    }

    template <typename ParamType, typename... Args>
    void _log(const ParamType& param, const Args &...args)
    {
        _log(param);
        (_log(args), ...);
    }

    template <typename... Args> void log(const Args &...args)
    {
        setvbuf(LOG_DEV_FILE, nullptr, _IONBF, 0);
        std::lock_guard<std::mutex> lock(log_mutex);
        debug::_log(args...);
        LOG_DEV << std::flush;
        fflush(LOG_DEV_FILE);
    }
}

#endif // LOG_HPP
