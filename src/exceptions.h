#pragma once

#define FWD(...) static_cast<decltype(__VA_ARGS__)&&>(__VA_ARGS__)

/**
 * Generic runtime error wrapper for formatted messages.
 */
namespace omnifix
{
    class error final: public std::runtime_error
    {
        public:
            template <typename... Args>
            explicit error(std::format_string<Args...> fmt, Args&&... args):
                std::runtime_error { std::format(fmt, FWD(args)...) } {}
    };
}