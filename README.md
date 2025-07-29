# omnifix
[![Build](https://github.com/aixxe/omnifix/actions/workflows/Build-MSVC.yml/badge.svg)](https://github.com/aixxe/omnifix/actions/workflows/Build-MSVC.yml)
[![Build](https://github.com/aixxe/omnifix/actions/workflows/Build-LLVM.yml/badge.svg)](https://github.com/aixxe/omnifix/actions/workflows/Build-LLVM.yml)
[![Build](https://github.com/aixxe/omnifix/actions/workflows/Build-GCC.yml/badge.svg)](https://github.com/aixxe/omnifix/actions/workflows/Build-GCC.yml)

Omnimix patches for beatmania IIDX implemented as a hook library

- Automatically discovers and applies all necessary patches
- Fixes clear & full-combo rates not displaying for all charts
- Uses lightning model files for subscreen searching if detected
- Option to show Omnimix charts with a distinct bar style in music select
- Includes music data & chart hashes for optional server-side validation

## Compatibility

The same `omnifix.dll` file can be used across all supported games:

- beatmania IIDX 31 EPOLIS
- beatmania IIDX 32 Pinky Crush

## Install

**To avoid conflicts, ensure any existing Omnimix patches are disabled before use!** This includes any pre-patched files such as `bm2dx_omni.dll` or Omnimix related patches applied at runtime via. spice2x, mempatch-hook, etc.

After you've confirmed this, download a pre-compiled version from the **[Releases](https://github.com/aixxe/omnifix/releases)** page

Copy the `omnifix.dll` file to your game directory and update your launcher options:

#### [spice2x](https://spice2x.github.io)

```
spice64.exe [...] -k omnifix.dll
```

#### [Bemanitools](https://github.com/djhackersdev/bemanitools)

```
launcher.exe [...] -K omnifix.dll
```

> [!TIP]
> If using [IFS LayeredFS](https://github.com/mon/ifs_layeredfs), ensure `ifs_hook.dll` is loaded **before** `omnifix.dll`

If any necessary files or patches could not be found, no changes will be made and the game will boot normally

Upon booting, the last character in the version string before the date should be `X`, e.g. `LDJ:J:D:X:2024100900`

<sub>※ If successful, the omnifix version is also displayed on the boot screen. This can be disabled with the <kbd>--omnifix-disable-boot-text</kbd> option</sub>

## Troubleshooting

Ensure your logging level is set to _at least_ `info` in `prop/avs-config.xml` (or `-loglevel info` with spice2x)

If using Bemanitools, you may also want to use the `-Y log.txt` launcher option to write log contents to a file

Related messages should appear in the log file, for example:

```
[2025/07/20 16:57:57] I:omnifix: omnifix v0.1.0 (master@3479ff70) loaded at 0x7ffaf55a0000
[2025/07/20 16:57:57] I:omnifix: built Jul 20 2025 17:57:52 with Clang 20.1.8
[2025/07/20 16:57:57] I:omnifix: detected game library 'bm2dx.dll' at 0x180000000
[2025/07/20 16:57:57] I:omnifix: enabling file path patches
[2025/07/20 16:57:57] I:omnifix: checking if file '/data/graphic/0/mdato.ifs' exists
[2025/07/20 16:57:57] I:omnifix: checking if file '/data/info/0/music_omni.bin' exists
[2025/07/20 16:57:57] I:omnifix: checking if file '/data/info/0//music_title_omni.xml' exists
[2025/07/20 16:57:57] I:omnifix: checking if file '/data/info/0//music_artist_omni.xml' exists
[2025/07/20 16:57:57] I:omnifix: checking if file '/data/info/0/video_music_omni.xml' exists
[2025/07/20 16:57:57] W:omnifix: optional file '/data/info/0/video_music_omni.xml' not found
[2025/07/20 16:57:57] I:omnifix: using custom 'X' revision code
[2025/07/20 16:57:57] I:omnifix: enabling leggendaria fix patches
[2025/07/20 16:57:57] I:omnifix: enabling clear rate hooks
[2025/07/20 16:57:57] I:omnifix: enabling music data buffer patches
[2025/07/20 16:57:57] I:omnifix: enabling xrpc services metadata hook
[2025/07/20 16:57:57] I:omnifix: enabling xrpc music metadata hook
[2025/07/20 16:57:57] I:omnifix: initialized successfully in 0.06 seconds
```

Set the log level to `misc` for even more detailed messages, e.g.

```
[2025/07/20 16:57:57] M:omnifix: applying patch at 0x1805e5b9c (size: 1)
[2025/07/20 16:57:57] M:omnifix:   - original: eb
[2025/07/20 16:57:57] M:omnifix:   - modified: 75
[2025/07/20 16:57:57] M:omnifix: applying patch at 0x180863294 (size: 2)
[2025/07/20 16:57:57] M:omnifix:   - original: 90 90
[2025/07/20 16:57:57] M:omnifix:   - modified: 74 25
```

## Options

Some functionality can be controlled through command-line options:

> ##### `--omnifix-disable-omnimix`
> Disable Omnimix patches. Useful if you only want network metadata or the clear rate fix hooks

> ##### `--omnifix-disable-clear-rate-fix`
> Disables hooks for raising the limit of how many clear & full combo rates can be stored by the game

> ##### `--omnifix-disable-xrpc-meta`
> Prevent omnifix version information and music chart hashes from being added to outgoing requests

> ##### `--omnifix-enable-unlock-all`
> Enables the 'Unlock All Songs and Charts' patch. **Not recommended when playing online**

> ##### `--omnifix-disable-boot-text`
> Disables the omnifix version text from being displayed on the boot screen

> ##### `--omnifix-enable-banner-hook`
> Display Omnimix exclusive charts with a distinct banner color in music select

> ##### `--omnifix-revision-code=X`
> Replaces the default `X` revision code with a custom one. Single character only

## Network validation

By default, omnifix will append additional metadata to the initial services request and new score submissions

The services request on boot will include the SHA-256 hash of the `data/info/#/music_omni.bin` file. This can be used by network operators to block unsupported versions from booting when a new update is available

<details><summary><b>Example services request</b></summary>

```xml
<?xml version="1.0" encoding="Shift-JIS"?>
<call model="LDJ:J:D:X:2024100900" srcid="00000000000000000000" tag="00000000">
  <services method="get">
    <omnifix branch="master" commit="3479ff70" version="0.1.0">
      <mdb_hash __type="bin" __size="32">ca58c3de8670c29bd8e649c2cbf9f34bc29bbca705ffa048d6c24aec3d3baa66</mdb_hash>
    </omnifix>
    <info></info>
    <net></net>
  </services>
</call>
```

</details>

Every newly submitted score will also include a SHA-256 hash of the chart, obtained by seeking to the relevant offset and reading the amount of bytes specified in the `.1` [directory](https://github.com/SaxxonPike/rhythm-game-formats/blob/master/iidx/1.md#directory) entry for the current difficulty

<details><summary><b>Example score save request</b></summary>

```xml
<?xml version="1.0" encoding="Shift-JIS"?>
<call model="LDJ:J:D:X:2024100900" srcid="00000000000000000000" tag="00000000">
  <IIDX32music method="reg">
    <ghost></ghost>
    <ghost_gauge></ghost_gauge>
    <music_play_log></music_play_log>
    <best_result></best_result>
    <omnifix branch="master" commit="3479ff70" version="0.1.0">
      <chart_hash __type="bin" __size="32">35d09686bdca856337ba44844a58672b4421c3084bb6e22a204c2c984e361052</chart_hash>
    </omnifix>
  </IIDX32music>
</call>
```

</details>

## Acknowledgements

- [**AllanCat**](https://github.com/AllanCat) for the increased music data buffer patch
- [**dogelition_man**](https://github.com/ledoge) for the original rate fix implementation