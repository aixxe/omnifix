#pragma once

#include <span>
#include <cstdint>
#include <string_view>
#include <minwindef.h>

namespace omnifix::memory
{
    class patch
    {
        using patch_data = std::vector<std::uint8_t>;

        public:
            patch(std::uint8_t* ptr, std::ranges::range auto bytes):
                _ptr { ptr }, _modified { std::begin(bytes), std::end(bytes) }
            {
                _original.resize(_modified.size());
                std::copy_n(_ptr, _modified.size(), _original.begin());
            }

            patch(std::uint8_t* ptr, std::initializer_list<std::uint8_t>&& bytes):
                patch(ptr, std::span { bytes }) {}

            ~patch();

            patch(const patch&) = delete;
            patch& operator=(const patch&) = delete;

            patch(patch&&) = default;
            patch& operator=(patch&&) = default;

            auto enable() -> void;
            auto disable() -> void;
        private:
            auto apply(const patch_data& data, bool enabled) -> void;

            bool _enabled {};
            DWORD _protect {};
            std::uint8_t* _ptr;
            patch_data _original;
            patch_data _modified;
    };

    auto find(std::span<std::uint8_t> region,
        std::string_view pattern, bool silent = false) -> std::uint8_t*;
    auto rfind(std::span<std::uint8_t> region,
        std::string_view pattern, bool silent = false) -> std::uint8_t*;

    template <typename T>
    auto find(const std::span<std::uint8_t> region,
        const std::string_view pattern, const bool silent = false) -> T
    {
        return reinterpret_cast<T>(find(region, pattern, silent));
    }

    template <typename T>
    auto rfind(const std::span<std::uint8_t> region,
        const std::string_view pattern, const bool silent = false) -> T
    {
        return reinterpret_cast<T>(rfind(region, pattern, silent));
    }

    auto to_pattern(std::string_view bytes,
        std::optional<char> wildcard = std::nullopt) -> std::string;

    auto follow(std::uint8_t* ptr, std::int64_t operand = -1) -> std::uint8_t*;
}