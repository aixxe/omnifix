#include <format>
#include <string>
#include <vector>
#include <ranges>
#include <algorithm>
#include <windows.h>
#include <system_error>
#include <Zydis/Zydis.h>

#include "exceptions.h"
#include "memory.h"

using namespace omnifix;

memory::patch::~patch()
    { disable(); }

auto memory::patch::enable() -> void
    { apply(_modified, true); }

auto memory::patch::disable() -> void
    { apply(_original, false); }

/**
 * Modify bytes at the designated memory location.
 *
 * @param data One or more bytes to write to the memory location.
 * @param enabled New 'enabled' state for this patch.
 */
auto memory::patch::apply(const patch_data& data, const bool enabled) -> void
{
    if (_enabled == enabled || data.empty())
        return;

    auto access = DWORD {};

    if (!VirtualProtect(_ptr, data.size(), PAGE_EXECUTE_READWRITE, &access))
    {
        auto const w32_error = std::system_category()
            .default_error_condition(static_cast<int>(GetLastError()));

        throw error { "failed to change memory protection at {:#x} ({})",
            std::bit_cast<std::uintptr_t>(_ptr), w32_error.message() };
    }

    std::ranges::copy(data, _ptr);
    VirtualProtect(_ptr, data.size(), access, &_protect);

    _protect = access;
    _enabled = enabled;
}

/**
 * Search for an 'IDA-style' pattern in a memory region.
 *
 * @param method Search algorithm method to use. (e.g. `std::ranges::search`))
 * @param region The memory region to search, represented as a span of bytes.
 * @param pattern The pattern to search for, e.g. "AA BB ? DD".
 * @param silent If true, suppresses exceptions when the pattern is not found.
 * @return Pointer to the first byte of the pattern.
 */
auto find_generic(auto&& method, auto&& region,
    auto&& pattern, const bool silent) -> std::uint8_t*
{
    auto offset = std::optional<std::size_t> {};
    auto target = std::vector<std::optional<std::uint8_t>> {};

    for (auto&& range: pattern | std::views::split(' '))
    {
        auto hex = std::string_view { range };
        auto bin = std::optional<std::uint8_t> {};

        if (hex.empty())
            continue;

        if (!offset && hex.starts_with('[') && hex.ends_with(']'))
        {
            hex = hex.substr(1, hex.size() - 2);
            offset = target.size();
        }

        if (!hex.starts_with('?'))
            bin = std::stoi(hex.data(), nullptr, 16);

        target.emplace_back(bin);
    }

    auto result = method(region, target, [] (auto a, auto b)
        { return !b || a == *b; });

    if (result.empty() && !silent)
        throw error { "pattern '{}' not found", pattern };

    return !result.empty() ? result.data() + offset.value_or(0): nullptr;
}

/**
 * Search forwards for an 'IDA-style' pattern in a memory region.
 *
 * @param region The memory region to search, represented as a span of bytes.
 * @param pattern The pattern to search for, e.g. "AA BB ? DD".
 * @param silent If true, suppresses exceptions when the pattern is not found.
 * @return Pointer to the first byte if found, else `std::nullopt`.
 */
auto memory::find(std::span<std::uint8_t> region,
    std::string_view pattern, const bool silent) -> std::uint8_t*
{
    return find_generic(std::ranges::search, region, pattern, silent);
}

/**
 * Search for an 'IDA-style' pattern in a memory region, starting from the end.
 *
 * @param region The memory region to search, represented as a span of bytes.
 * @param pattern The pattern to search for, e.g. "AA BB ? DD".
 * @param silent If true, suppresses exceptions when the pattern is not found.
 * @return Pointer to the first byte if found, else `std::nullopt`.
 */
auto memory::rfind(std::span<std::uint8_t> region,
    std::string_view pattern, const bool silent) -> std::uint8_t*
{
    return find_generic(std::ranges::find_end, region, pattern, silent);
}

/**
 * Given a string, convert it into a pattern usable for scanning.
 *
 * @param bytes The input string to convert, e.g. "he?lo!".
 * @param wildcard Character to treat as a wildcard. `std::nullopt` to disable.
 * @return Converted 'pattern' string, e.g. "68 65 ? 6C 6F 21".
 */
auto memory::to_pattern(std::string_view bytes,
    std::optional<char> wildcard) -> std::string
{
    auto result = bytes
        | std::views::transform([wildcard] (char c) -> std::string
            { return c == wildcard ? "? ": std::format("{:02X} ", c); })
        | std::views::join
        | std::ranges::to<std::string>();

    if (!result.empty())
        result.pop_back();

    return result;
}

/**
 * Calculates an absolute address from an instruction containing a relative one.
 *
 * @param ptr Pointer to the first byte of an instruction to decode.
 * @param operand Operand to use for calculation. Defaults to auto-detection.
 * @return Pointer to the absolute address calculated from the instruction.
 */
auto memory::follow(std::uint8_t* ptr, std::int64_t operand) -> std::uint8_t*
{
    auto decoder = ZydisDecoder {};
    auto status = ZydisDecoderInit
        (&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    if (!ZYAN_SUCCESS(status))
        throw std::runtime_error { "failed to initialize decoder" };

    auto instruction = ZydisDecodedInstruction {};
    auto operands = std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> {};

    status = ZydisDecoderDecodeFull
        (&decoder, ptr, 32, &instruction, operands.data());

    if (!ZYAN_SUCCESS(status))
        throw std::runtime_error { "failed to decode instruction" };

    if (operand == -1)
    {
        operand = 0;

        auto const it = std::ranges::find_if(operands, [] (auto&& op)
            { return op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (op.mem.base == ZYDIS_REGISTER_RIP ||
                     op.mem.base == ZYDIS_REGISTER_EIP); });

        if (it != operands.end())
            operand = std::distance(operands.begin(), it);
    }

    auto rip = std::bit_cast<ZyanU64>(ptr);
    auto result = ZyanU64 {};

    status = ZydisCalcAbsoluteAddress
        (&instruction, &operands[operand], rip, &result);

    if (!ZYAN_SUCCESS(status))
        throw error { "failed to calculate absolute address at {:#x}", rip };

    return reinterpret_cast<std::uint8_t*>(result);
}