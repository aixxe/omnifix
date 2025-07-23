#pragma once

namespace bm2dx
{
    struct mdb
    {
        /* 0x0000 */ std::uint8_t magic[4];
        /* 0x0004 */ std::int32_t version;
    };

    struct mdb_v31
    {
	    using index_type = std::int16_t;

        auto static constexpr level_offset = 0x120;
        auto static constexpr index_offset = 0x3B0;

        /* 0x0000 */ std::uint8_t magic[4];
        /* 0x0004 */ std::int32_t version;
        /* 0x0008 */ std::int16_t entries;
        /* 0x000A */ std::int16_t max_entries;
        /* 0x000C */ std::uint8_t pad_000C[4];
    };

    struct mdb_v32
    {
	    using index_type = std::int32_t;

        auto static constexpr level_offset = 0x3EC;
        auto static constexpr index_offset = 0x67C;

        /* 0x0000 */ std::uint8_t magic[4];
        /* 0x0004 */ std::int32_t version;
        /* 0x0008 */ std::int32_t entries;
        /* 0x000C */ std::int32_t max_entries;
    };
}