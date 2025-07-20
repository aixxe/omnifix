#pragma once

namespace avs2
{
    using node_ptr = void*;
    using property_ptr = void*;
    using file_type = std::int32_t;

    enum node_type
    {
        node_type_node = 0x001,
        node_type_bin  = 0x00A,
        node_type_attr = 0x02E,
    };

    struct file_stat
    {
        /* 0x0000 */ std::time_t atime;
        /* 0x0008 */ std::time_t mtime;
        /* 0x0010 */ std::time_t ctime;
        /* 0x0018 */ std::uint8_t pad_0018[4];
        /* 0x001C */ std::uint32_t size;
        /* 0x0020 */ std::uint8_t pad_0020[48];
    }; static_assert(sizeof(file_stat) == 0x50);

    extern "C"
    {
        auto log_body_info(const char* module, const char* fmt, ...) -> void;
        auto log_body_misc(const char* module, const char* fmt, ...) -> void;
        auto log_body_warning(const char* module, const char* fmt, ...) -> void;

        auto fs_open(const char* path, uint16_t mode, int flags) -> file_type;
        auto fs_close(file_type handle) -> file_type;
        auto fs_fstat(file_type handle, file_stat* stat) -> bool;
        auto fs_read(file_type handle, void* bytes, size_t size) -> size_t;

        auto property_node_create(property_ptr prop, node_ptr node,
            node_type type, const char* path, ...) -> node_ptr;
        auto property_node_refer(property_ptr prop, node_ptr node,
            const char* path, node_type type, void* data, uint32_t size) -> int;
    }

    namespace log
    {
        auto constexpr module = "omnifix";

        template <typename... Args>
        auto constexpr info(std::format_string<Args...> fmt, Args&&... args)
        {
            log_body_info(module, "%s", std::format(fmt,
                std::forward<Args>(args)...).c_str());
        }

        template <typename... Args>
        auto constexpr misc(std::format_string<Args...> fmt, Args&&... args)
        {
            log_body_misc(module, "%s", std::format(fmt,
                std::forward<Args>(args)...).c_str());
        }

        template <typename... Args>
        auto constexpr warning(std::format_string<Args...> fmt, Args&&... args)
        {
            log_body_warning(module, "%s", std::format(fmt,
                std::forward<Args>(args)...).c_str());
        }
    }

    namespace file
    {
        /**
         * Checks if a file exists by attempting to open it.
         *
         * @param path Path to a file within an AVS2 filesystem.
         * @return True if the file exists, false otherwise.
         */
        auto inline exists(const std::string_view path)
        {
            log::info("checking if file '{}' exists", path);
            auto const handle = fs_open(path.data(), 1, 0x1A4);

            if (handle < -1)
                return false;

            fs_close(handle);
            return true;
        }

        /**
         * Opens and reads the contents of a file.
         *
         * @param path Path to a file within an AVS2 filesystem.
         * @return Vector of bytes containing the file contents.
         */
        auto inline read(const std::string_view path)
        {
            auto result = std::vector<std::uint8_t> {};
            auto const handle = fs_open(path.data(), 1, 0x1A4);

            if (!handle)
            {
                log::warning("failed to open '{}'", path);
                return result;
            }

            auto stat = file_stat {};

            if (!fs_fstat(handle, &stat) || !stat.size)
            {
                log::warning("failed to stat '{}'", path);
                fs_close(handle);
                return result;
            }

            result.resize(stat.size);

            fs_read(handle, result.data(), stat.size);
            fs_close(handle);

            return result;
        }
    }
}