#include <array>
#include <format>
#include <ranges>
#include <cstring>
#include <windows.h>
#include <picosha2.h>
#include <unordered_set>
#include <safetyhook.hpp>

#include "avs2.h"
#include "bm2dx.h"
#include "memory.h"
#include "modules.h"
#include "exceptions.h"

using namespace omnifix;

using hash_type = std::array<std::uint8_t, picosha2::k_digest_size>;

auto constexpr expected_game_symbol = "dll_entry_main";
auto constexpr music_data_buffer_size = std::uint32_t { 0x600000 };

auto mdb_path = std::string_view {};
auto override_revision_code = std::uint8_t { 'X' };

auto patches = std::vector<memory::patch> {};

/**
 * Helper method to create a patch with some logging text.
 *
 * @param ptr Pointer to memory where the patch will be applied.
 * @param bytes One or more bytes to write to the memory location.
 */
auto add_patch(std::uint8_t* ptr, std::ranges::range auto bytes)
{
    auto original = std::string {};
    auto modified = std::string {};

    for (auto i = 0u; i < bytes.size(); ++i)
    {
        original += std::format("{:02x} ", *(bytes.begin() + i));
        modified += std::format("{:02x} ", ptr[i]);
    }

    original.pop_back();
    modified.pop_back();

    avs2::log::misc("applying patch at {:#x} (size: {})",
        std::bit_cast<std::uintptr_t>(ptr), bytes.size());

    avs2::log::misc("  - original: {}", original);
    avs2::log::misc("  - modified: {}", modified);

    patches.emplace_back(ptr, bytes);
}

auto add_patch(std::uint8_t* ptr, std::initializer_list<std::uint8_t>&& bytes)
    { return add_patch(ptr, std::span { bytes }); }

/**
 * Helper method to create a node and populate common properties.
 *
 * @param node Pointer to an AVS2 node to append to.
 * @return Newly created node for adding request-specific data.
 */
auto create_common_node(avs2::node_ptr* node) -> avs2::node_ptr
{
    auto const result = avs2::property_node_create
        (nullptr, node, avs2::node_type_node, "omnifix");

    avs2::property_node_create(nullptr, result, avs2::node_type_attr,
        "branch@", META_GIT_BRANCH);
    avs2::property_node_create(nullptr, result, avs2::node_type_attr,
        "commit@", META_GIT_COMMIT_SHORT);
    avs2::property_node_create(nullptr, result, avs2::node_type_attr,
        "version@", META_PROJECT_VERSION);

    return result;
}

/**
 * Return the first found match from an array of patterns.
 *
 * @param region The memory region to search, represented as a span of bytes.
 * @param patterns Array of patterns to search through.
 * @return Pointer to the first byte if found, else `std::nullopt`.
 */
auto find_first_pattern(auto&& region, auto&& patterns)
    -> std::optional<std::uint8_t*>
{
    auto scans = patterns | std::views::transform([&] (auto&& pattern)
        { return memory::find(region, pattern, true); });

    for (auto&& element: scans)
        if (element != nullptr)
            return element;

    return std::nullopt;
}

/**
 * Return pointer to the music data file path.
 */
auto find_music_data_bin_path(auto&& bm2dx) -> std::string_view
{
    return std::string_view { memory::find<const char*>(bm2dx,
        memory::to_pattern("/data/info/") + " ? " +
        memory::to_pattern("/music_") + " ? ? ? ? " +
        memory::to_pattern(".bin")
    ) };
}

/**
 * Alter the texture path for custom graphics.
 */
auto patch_mdata_ifs_path(auto ptr)
{
    auto constexpr offset = 7;
    auto path = std::string { reinterpret_cast<const char*>(ptr) };

    path[offset] = 'o';

    if (!avs2::file::exists("/data/graphic" + path))
        throw error { "required file '/data/graphic{}' not found", path };

    add_patch(ptr + offset, { 'o' });
}

/**
 * Alter the path to the music database.
 */
auto patch_music_data_bin_path(auto ptr)
{
    auto constexpr offset = 19;
    auto path = std::string { reinterpret_cast<const char*>(ptr) };

    path.replace(offset, 4, "omni");

    if (!avs2::file::exists(path))
        throw error { "required file '{}' not found", path };

    add_patch(ptr + offset, { 'o', 'm', 'n', 'i' });
}

/**
 * Alter the subscreen music title XML path.
 */
auto patch_music_title_xml_path(auto ptr)
{
    auto constexpr offset = 26;
    auto path = std::string { reinterpret_cast<const char*>(ptr) };

    path.replace(offset, 4, "omni");

    if (!avs2::file::exists(path))
        return avs2::log::warning("optional file '{}' not found", path);

    add_patch(ptr + offset, { 'o', 'm', 'n', 'i' });
}

/**
 * Alter the subscreen music artist XML path.
 */
auto patch_music_artist_xml_path(auto ptr)
{
    auto constexpr offset = 27;
    auto path = std::string { reinterpret_cast<const char*>(ptr) };

    path.replace(offset, 4, "omni");

    if (!avs2::file::exists(path))
        return avs2::log::warning("optional file '{}' not found", path);

    add_patch(ptr + offset, { 'o', 'm', 'n', 'i' });
}

/**
 * Alter the video music list XML path.
 */
auto patch_video_music_list_xml_path(auto ptr)
{
    auto constexpr offset = 25;
    auto path = std::string { reinterpret_cast<const char*>(ptr) };

    path.replace(offset, 4, "omni");

    if (!avs2::file::exists(path))
        return avs2::log::warning("optional file '{}' not found", path);

    add_patch(ptr + offset, { 'o', 'm', 'n', 'i' });
}

/**
 * Load thumbnails in music select for entries below ID 10000.
 */
auto patch_thumbnail_file_path(auto&& bm2dx)
{
    auto constexpr prefix = "/data/graphic/thumbnail/";
    auto constexpr bytes = std::to_array("%d_thum.png");

    if (auto ptr = memory::find(bm2dx, memory::to_pattern(prefix), true))
        add_patch(ptr + std::strlen(prefix), bytes);
}

/**
 * Find and alter paths to point to custom files.
 */
auto setup_omnimix_path_patch(auto&& bm2dx)
{
    avs2::log::info("enabling file path patches");

    // Ensure the mandatory files exist before continuing.
    patch_mdata_ifs_path(memory::follow(memory::find(bm2dx,
        "48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8D 3D ? ? ? ? 4C 89 3D")));

    patch_music_data_bin_path(memory::follow(memory::find(bm2dx,
        "48 8D 15 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 8B D8 85 C0")));

    // Optional files for LIGHTNING MODEL features.
    auto const prefix = memory::to_pattern("/data/info/");

    patch_music_title_xml_path(memory::find(bm2dx,
        prefix + " ? " + memory::to_pattern("//music_title_")));

    patch_music_artist_xml_path(memory::find(bm2dx,
        prefix + " ? " + memory::to_pattern("//music_artist_")));

    patch_video_music_list_xml_path(memory::find(bm2dx,
        prefix + " ? " + memory::to_pattern("/video_music_")));

    // More optional stuff for IIDX 32.
    patch_thumbnail_file_path(bm2dx);
}

/**
 * Early patch to override the revision code.
 */
auto setup_revision_patch(auto&& bm2dx)
{
    avs2::log::info("using custom '{}' revision code",
        static_cast<char>(override_revision_code));

    // Ensures the condition for the second part is always met.
    auto target = memory::find(bm2dx, "40 84 F6 ? ? 48 85 FF");
    add_patch(target + 3, { 0xEB, 0x30 });

    // Patch that actually replaces the revision code.
    target = memory::find({ target, target + 0x100 }, "C6 47 ? ? BA");
    add_patch(target + 3, { override_revision_code });
}

/**
 * Fixes for LEGGENDARIA charts in music select.
 */
auto setup_leggendaria_patch(auto&& bm2dx)
{
    avs2::log::info("enabling leggendaria fix patches");

    // Fixes titles not appearing purple when hovered over in music select.
    auto target = memory::find(bm2dx, "84 C0 ? ? FF C3 48 83 C7");
    add_patch(target + 2, { 0xEB });

    // Fixes non-default charts not appearing in the LEGGENDARIA folder.
    target = memory::find(bm2dx, "E8 ? ? ? ? 48 8B CE E8 ? ? ? ? 84 C0 74 ? 8B D3");
    target = memory::find({ memory::follow(target), 0x100 }, "84 C0 ? ? E8");
    add_patch(target + 2, { 0x90, 0x90 });
}

/**
 * Allocates a larger buffer for the music data file.
 */
auto setup_music_data_buffer_patch(auto&& bm2dx)
{
    avs2::log::info("enabling music data buffer patches");

    // Find the function responsible for loading the 'music_data.bin' file.
    auto base = memory::follow(memory::find(bm2dx,
        "E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 33 C0"));

    // Jump ahead to a call that returns the static buffer for the file.
    base = memory::find({ base, base + 0x100 }, "BB 32 00 00 00 EB ? E8");
    auto const buffer = reinterpret_cast<void**>
        (memory::follow(memory::follow(base + 7)));

    // Patch out a check that fails if the custom database has too many songs.
    base = memory::find({ base, base + 0x100 }, "E8 ? ? ? ? 48 8B C8");
    add_patch(base - 2, { 0x90, 0x90 });

    // Patch another check that fails if the file on disk is too large.
    add_patch(memory::find(bm2dx, "48 81 F9 ? ? ? ? 76 ? BB") + 3, {
        music_data_buffer_size       & 0xFF,
        music_data_buffer_size >>  8 & 0xFF,
        music_data_buffer_size >> 16 & 0xFF,
        music_data_buffer_size >> 24 & 0xFF,
    });

    // Allocate a larger buffer where the file will be read into.
    auto static new_buffer = new std::uint8_t[music_data_buffer_size] {};
    buffer[0] = new_buffer;
    buffer[2] = new_buffer + 0x10;

    // Hook the file read call to write into the new buffer instead.
    auto target = memory::find(bm2dx, "FF 15 ? ? ? ? 85 C0 79 ? BB");
    auto static music_data_read_hook = safetyhook::create_mid(target,
        [] (SafetyHookContext& ctx) -> void
    {
        ctx.rdx = reinterpret_cast<std::uintptr_t>(new_buffer);
        ctx.r8  = music_data_buffer_size;
    });

    // Finally, patch all references to the music data buffer.
    target = memory::find(bm2dx, "E8 ? ? ? ? 85 C0 78 ? 48 8B 0D");
    target = memory::follow(target);
    target = memory::find({ target, target + 0x100 }, "48 ? 0D");
    add_patch(target + 1, { 0x8B });

    target = memory::find(bm2dx, "E8 ? ? ? ? 48 8B F8 83 B8");
    target = memory::follow(target);
    target = memory::find({ target, target + 0x100 }, "48 ? 05");
    add_patch(target + 1, { 0x8B });

    target = memory::find(bm2dx, "E8 ? ? ? ? 48 85 C0 B9");
    target = memory::follow(target);
    target = memory::find({ target, target + 0x100 }, "48 ? 0D");
    add_patch(target + 1, { 0x8B });

    target = memory::find(bm2dx, "E8 ? ? ? ? 33 FF 8B F7");
    target = memory::follow(target);
    add_patch(target + 1, { 0x8B });
}

/**
 * Unlocks all charts. Redundant if implemented server-side.
 */
auto setup_chart_unlock_patch(auto&& bm2dx)
{
    avs2::log::info("enabling chart unlock patch");

    auto target = memory::find(bm2dx, "E8 ? ? ? ? 84 C0 74 ? 42 0F BE 8C 3D");
    target = memory::find({ memory::follow(target), 0x100 },
        "48 8B 5C 24 40 ? ? 48 8B 74 24 48 48 83 C4 30 5F C3 CC");
    add_patch(target + 5, { 0xB0, 0x01 });
}

/**
 * Fixes clear rates not displaying when too many results are sent.
 */
auto setup_clear_rate_hook(auto&& bm2dx)
{
    avs2::log::info("enabling clear rate hooks");

    // How many items to read from each clear rate response node.
    // 5 difficulties * 2 play styles * 2 rate types = 20 items
    auto constexpr item_count = 20;

    // Response handler function for the 'IIDX--music.crate' XRPC method.
    auto crate_recv_fn = memory::find(bm2dx, "C7 44 24 ? ? ? ? ? C7 44 24 "
        "? ? ? ? ? C7 44 24 ? ? ? ? ? EB ? 8B 44 24");

    // Functions to get rate data for a specific music ID and difficulty.
    auto clear_rate_fn = memory::find(bm2dx, "E8 ? ? ? ? 85 C0 8B 44 24");
    auto fc_rate_fn = memory::find(bm2dx, "E8 ? ? ? ? EB ? 41 8B 89");

    auto static rates = std::unordered_map
        <std::uint32_t, std::array<std::int32_t, item_count>> {};

    auto static read_rate_hook = safetyhook::create_mid(crate_recv_fn,
        [] (SafetyHookContext& ctx) -> void
    {
        // Copy all data we received from the response. The game only stores a
        // fixed amount of these, but that check happens a bit later, so we're
        // guaranteed to read everything when we hook here.
        auto const id = *reinterpret_cast<std::uint32_t*>(ctx.rsp + 0x40);
        auto const data = reinterpret_cast<std::int32_t*>(ctx.rsp + 0x80);

        std::copy_n(data, item_count, rates[id].begin());
    });

    auto static clear_rate_hook = safetyhook::InlineHook {};
    auto static fc_rate_hook = safetyhook::InlineHook {};

    clear_rate_hook = safetyhook::create_inline(memory::follow(clear_rate_fn),
        +[] (const int id, const int difficulty, int* rate) -> bool
    {
        if (!rates.contains(id))
            return false;

        *rate = rates[id][difficulty];

        return true;
    });

    fc_rate_hook = safetyhook::create_inline(memory::follow(fc_rate_fn),
        +[] (const int id, const int difficulty, int* rate) -> bool
    {
        if (!rates.contains(id))
            return false;

        // Full combo rates appear directly after regular clear rates.
        *rate = rates[id][difficulty + item_count / 2];

        return true;
    });
}

/**
 * Iterate over music data entries and construct a map of charts.
 */
template <typename header_type>
auto iterate_mdb_entries(auto&& buffer)
{
    using index_type = typename header_type::index_type;
    using chart_map = std::unordered_map<int, std::array<std::uint8_t, 10>>;

    auto const header = std::bit_cast<const header_type*>(buffer.data());

    auto constexpr index_size = sizeof(index_type);
    auto constexpr header_size = sizeof(header_type);

    auto const directory = reinterpret_cast<const index_type*>
        (buffer.data() + header_size);

    auto const entry_first = header_size + header->max_entries * index_size;
    auto const entry_size = (buffer.size() - entry_first) / header->entries;

    auto seen = std::unordered_set<int> {};
    auto charts = chart_map {};

    for (auto id = 0; id < header->max_entries; ++id)
    {
        auto const index = directory[id];

        if (index == -1 || seen.contains(index))
            continue;

        seen.insert(index);

        auto const entry = entry_first + index * entry_size;
        auto const ratings = buffer.data() + entry + header_type::level_offset;

        std::copy_n(ratings, charts[id].size(), charts[id].data());
    }

    return std::make_pair(header->version, charts);
}

/**
 * Read and parse a music data file from any supported version.
 */
auto parse_music_data_file(auto&& path)
{
    auto const buffer = avs2::file::read(path);
    auto const header = reinterpret_cast<const bm2dx::mdb*>(buffer.data());

    if (buffer.empty() || std::memcmp(header->magic, "IIDX", 4) != 0)
        throw error { "failed to read music data file '{}'", path };

    if (header->version == 31)
        return iterate_mdb_entries<bm2dx::mdb_v31>(buffer);
    if (header->version == 32)
        return iterate_mdb_entries<bm2dx::mdb_v32>(buffer);

    throw error { "unsupported version {} in '{}'", header->version, path };
}

/**
 * Display Omnimix charts using a distinct song bar texture.
 */
auto setup_song_banner_hook(auto&& bm2dx)
{
    avs2::log::info("enabling song banner hook");

    // Color Omnimix charts using the "listb_lightning" bar texture.
    auto constexpr omnimix_bar_style = 2;

    // Build paths to both original and modified music data files.
    auto path_original = std::string { "/data/info/#/music_data.bin" };
    auto path_modified = std::string { "/data/info/#/music_omni.bin" };

    // Set the `0` or `1` in each path, which alternates each style.
    path_original.at(11) = mdb_path.at(11);
    path_modified.at(11) = mdb_path.at(11);

    auto [ver_original, mdb_original] = parse_music_data_file(path_original);
    auto [ver_modified, mdb_modified] = parse_music_data_file(path_modified);

    if (ver_original != ver_modified)
        throw error { "version mismatch between music data files" };

    // Compare the two files and create a map of unique charts.
    auto static unique = std::unordered_map<int, std::array<bool, 10>> {};

    for (auto const& [index, ratings]: mdb_modified)
        for (auto i = 0u; i < ratings.size(); ++i)
            if (ratings[i] != mdb_original[index][i])
                unique[index][i] = ratings[i] > 0;

    // Set up some version-specific context for the hook.
    auto static const index_offset = ver_original == 31 ?
        bm2dx::mdb_v31::index_offset: bm2dx::mdb_v32::index_offset;

    // Find a function that sets up category bars during music select init.
    auto const target = memory::find(bm2dx, "4C 8B DC 49 89 53 ? 55");
    auto static hook = safetyhook::InlineHook {};

    hook = safetyhook::create_inline(target, +[] (std::uint8_t* bar,
        std::uint8_t* entry, int chart, int style, int a5, int a6)
    {
        auto const result = hook.call<bool>(bar, entry, chart, style, a5, a6);

        // View of the bar styles for this music entry - one per chart.
        // In order: BEGINNER, NORMAL, HYPER, ANOTHER, LEGGENDARIA.
        auto const charts = std::span { reinterpret_cast<int*>(bar + 0x20), 5 };

        // Reset anything using our designated bar style to default.
        std::ranges::transform(charts, charts.begin(),
            [] (auto&& v) { return v == omnimix_bar_style ? 0: v; });

        // Check if the music entry for this bar is in the unique map.
        // If so, it is either an entirely unique song, or has unique charts.
        auto const index = *reinterpret_cast<int*>(entry + index_offset);

        if (unique.contains(index))
        {
            // View of the unique charts for this music entry.
            // Offset of 5 for DP charts, as the first 5 are always SP.
            auto const custom = std::span { unique.at(index) }
                .subspan(style == 1 ? 5: 0, charts.size());

            // If the chart is unique to Omnimix, override the bar style.
            for (auto&& [bar_style, is_unique]: std::views::zip(charts, custom))
                bar_style = is_unique ? omnimix_bar_style: bar_style;
        }

        return result;
    });
}

/**
 * Reports version information to the server on boot.
 */
auto setup_xrpc_services_get_hook()
{
    avs2::log::info("enabling xrpc services metadata hook");

    auto const ea3lib = modules::find("avs2-ea3.dll");
    auto const target = find_first_pattern(ea3lib.region(), std::array
    {
        // 2.17.4 (r8528)
        "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC ? 48 89 D3",

        // 2.17.3 (r8311)
        "55 48 83 EC 60 48 8D 6C 24 30 48 89 4D 40 48 89 55 48 48 "
        "C7 45 08 FE FF FF FF",

        // 2.17.0 (r7883)
        "55 48 83 EC 30 48 8D 6C 24 20 48 89 4D 20 48 89 55 28 48 "
        "C7 45 00 FE FF FF FF 48 8B 45 20 48 89 45 08 48 8B 55 08 "
        "48 8B 0A",
    });

    if (!target)
        throw error { "failed to find xrpc services.get hook target" };

    auto static services_get_hook = safetyhook::InlineHook {};

    services_get_hook = safetyhook::create_inline(*target,
        +[] (void* ctx, avs2::node_ptr* node) -> void*
    {
        auto hash = hash_type {};
        auto const buffer = avs2::file::read(mdb_path);

        if (buffer.empty())
            return nullptr;

        picosha2::hash256(buffer, hash);

        avs2::log::misc("added music db hash '{}' to services.get request",
            picosha2::bytes_to_hex_string(hash));

        auto const info = create_common_node(node);

        avs2::property_node_create(nullptr, info, avs2::node_type_bin,
            "mdb_hash", hash.data(), hash.size());

        return services_get_hook.call<void*>(ctx, node);
    });
}

/**
 * Reports chart hash to the server on score submission.
 */
auto setup_xrpc_music_reg_hook(auto&& bm2dx)
{
    avs2::log::info("enabling xrpc music metadata hook");

    // Functions where we'll be placing hooks.
    auto const chart_load_target = memory::find(bm2dx,
        "48 8D 4C 24 ? E8 ? ? ? ? 0F B6 C3 48 8B 8C 24");
    auto const music_reg_target = memory::find(bm2dx,
        "48 89 54 24 10 48 89 4C 24 08 48 81 EC A8 00 00 00 48 8B 84 24 B0");

    // Chart buffer pointer to use as a reference.
    auto static const chart_buffer_ptr = reinterpret_cast<void* (*) ()>
        (memory::follow(memory::find(bm2dx, "E8 ? ? ? ? B9 ? ? ? ? C6 80"))) ();

    // Static storage for hashes - one per player. We calculate these when the
    // chart is loaded, then read them back when the score is submitted.
    auto static hashes = std::array<hash_type, 2> {};

    auto static chart_load_hook = safetyhook::create_mid(chart_load_target,
        [] (SafetyHookContext& ctx) -> void
    {
        // Player is determined by the buffer pointer. If it matches the one we
        // scanned for earlier, it's for P1. Otherwise, assume it's for P2.
        auto const buffer = reinterpret_cast<std::uint8_t*>(ctx.rdi);
        auto const player = buffer == chart_buffer_ptr ? 0: 1;
        auto const size = static_cast<std::uint32_t>(ctx.rax);

        if (ctx.rbx & 0x1)
            picosha2::hash256(buffer, buffer + size, hashes[player]);
        else
            std::ranges::fill(hashes[player], 0);
    });

    auto static music_reg_hook = safetyhook::InlineHook {};

    music_reg_hook = safetyhook::create_inline(music_reg_target,
        +[] (void* ctx, avs2::node_ptr* node) -> void*
    {
        auto const result = music_reg_hook.call<void*>(ctx, node);

        // Read out the player side so we can link it to an already calculated
        // hash value. Attributes are always read out as strings.
        auto buffer = std::array<char, 8> {};

        avs2::property_node_refer(nullptr, node, "pside@",
            avs2::node_type_attr, buffer.data(), buffer.size());

        auto const side = std::stoi(buffer.data());

        if (side == 0 || side == 1)
        {
            auto const info = create_common_node(node);

            avs2::property_node_create(nullptr, info, avs2::node_type_bin,
                "chart_hash", hashes[side].data(), hashes[side].size());

            avs2::log::misc("added chart hash '{}' to p{} music.reg request",
                picosha2::bytes_to_hex_string(hashes[side]), side + 1);
        }

        return result;
    });
}

/**
 * Displays omnifix version information on the boot screen.
 */
auto setup_boot_text_hook(auto&& bm2dx)
{
    struct text_color { float r, g, b, a; };
    auto static color = text_color { 1.f, 1.f, 1.f, 1.f };

    using render_fn = void (*) (int, int, int, text_color*, const char*, ...);
    auto const static render_text = reinterpret_cast<render_fn>
        (memory::follow(memory::find(bm2dx, "E8 ? ? ? ? EB ? 8B 4D")));

    auto const target = memory::find(bm2dx, "0F 8C ? ? ? ? 80 7D ? ? ? ? B9");
    auto static boot_text_hook = safetyhook::create_mid(target + 6,
        [] (SafetyHookContext&) -> void
    {
        render_text(1, 60, 112 + (8 * 32), &color, "OMNIFIX");
        render_text(1, 300, 112 + (8 * 32), &color,
            ":<color 00ffffff>%s</color> <color ffffff30>(%s)</color>",
            META_PROJECT_VERSION, META_GIT_COMMIT_SHORT);
    });
}

auto init(std::uint8_t* module) -> int
{
    auto const start = std::chrono::steady_clock::now();

    avs2::log::info("omnifix v{} ({}@{}) loaded at {:#x}",
        META_PROJECT_VERSION, META_GIT_BRANCH, META_GIT_COMMIT_SHORT,
        std::bit_cast<std::uintptr_t>(module));

    avs2::log::info("built {} {} with {} {}",
        __DATE__, __TIME__, META_COMPILER_ID, META_COMPILER_VERSION);

    auto const list = modules::list();
    auto const bm2dx = std::ranges::find_if(list, [] (auto&& entry)
        { return modules::has_export(entry.base, expected_game_symbol); });

    if (bm2dx == list.end())
        throw std::runtime_error { "game library not found" };

    avs2::log::info("detected game library '{}' at {:#x}",
        bm2dx->path.filename().string(),
        std::bit_cast<std::uintptr_t>(bm2dx->base));

    auto const region = bm2dx->region();
    auto const [flags, options] = modules::argv();

    mdb_path = find_music_data_bin_path(region);

    if (options.contains("omnifix-revision-code"))
    {
        auto const revision = options.at("omnifix-revision-code");

        if (!revision.empty() && revision.size() == 1)
            override_revision_code = revision[0];
    }

    if (!flags.contains("omnifix-disable-omnimix"))
    {
        setup_omnimix_path_patch(region);
        setup_revision_patch(region);
        setup_leggendaria_patch(region);
        setup_music_data_buffer_patch(region);
    }

    if (flags.contains("omnifix-enable-unlock-all"))
        setup_chart_unlock_patch(region);

    if (!flags.contains("omnifix-disable-boot-text"))
        setup_boot_text_hook(region);

    if (!flags.contains("omnifix-disable-xrpc-meta"))
    {
        setup_xrpc_services_get_hook();
        setup_xrpc_music_reg_hook(region);
    }

    if (!flags.contains("omnifix-disable-clear-rate-fix"))
        setup_clear_rate_hook(region);

    if (flags.contains("omnifix-enable-banner-hook"))
        setup_song_banner_hook(region);

    for (auto&& patch: patches)
        patch.enable();

    auto const elapsed = std::chrono::steady_clock::now() - start;

    avs2::log::info("initialized successfully in {:.2f} seconds",
        std::chrono::duration_cast<std::chrono::duration<double>>(elapsed).count());

    return EXIT_SUCCESS;
}

auto DllMain(HINSTANCE module, DWORD reason, LPVOID) -> BOOL
{
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(module);
    
    try
    {
        init(reinterpret_cast<std::uint8_t*>(module));
        return TRUE;
    }
    catch (const std::exception& error)
    {
        avs2::log::warning("initialization error: {}", error.what());
        return FALSE;
    }
}