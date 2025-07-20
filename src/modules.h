#pragma once

#include <span>
#include <vector>
#include <windows.h>
#include <filesystem>

namespace omnifix::modules
{
    using dos_header_type = PIMAGE_DOS_HEADER;
    using nt_header_type = PIMAGE_NT_HEADERS;

    struct module_entry
    {
        std::uint8_t* base;
        std::size_t size;
        std::filesystem::path path;

        [[nodiscard]] auto region() const -> std::span<std::uint8_t>
            { return { base, size }; }
    };

    auto argv() -> std::vector<std::string>;
    auto list() -> std::vector<module_entry>;
    auto find(std::string_view name) -> module_entry;
    auto nt_header(std::uint8_t* module) -> nt_header_type;
    auto has_export(std::uint8_t* module, std::string_view symbol) -> bool;
}