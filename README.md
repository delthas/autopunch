# autopunch  ![](https://img.shields.io/github/downloads/delthas/autopunch/total.svg?style=flat-square)

**This program lets you host & connect to friends to play peer-to-peer games without having to open or redirect any port. This does not add any latency to the connection compared to redirecting ports manually.**

**You can play with users that don't use autopunch without compability issues and can always leave it enabled. However, the tool will only do its magic if both peers use autopunch.**

*Technical details: autopunch injects itself into a process and detours some winsock calls (sendto, recvfrom, ...) to rewrite addresses so that they appear to be internal ports rather than external ports. It additionally performs hole punching by using a STUN-like relay which helps know internal ports of other users.*  

## How to use

- **Download the latest version: for [Windows 64 bits](https://github.com/delthas/autopunch/releases/latest/download/autopunch.win64.exe) or [Windows 32 bits](https://github.com/delthas/autopunch/releases/latest/download/autopunch.win32.exe) (use one of these links, not any other download button)**
- **Start your peer-to-peer game** *(for Touhou Hisoutensoku players: also run SokuRoll now, if needed)*
- **Double-click the downloaded executable file to run it**; there is no setup or anything so put the file somewhere you'll remember (doesn't have to be in the game folder)
- If a Windows Defender SmartScreen popup appears, click on "More information", then click on "Run anyway"
- If a Windows Firewall popup appears, check the "Private networks" and "Public networks" checkboxes, then click on "Allow access"
- If prompted for an update, just wait, everything will be updated and restart automatically
- **Click on the game you wish to play in the list, then click "Punch!"**; the window will close and "autopunch" will appear in the game window title *(just like SokuRoll)*
- **Play!** Host on any port, or connect to the IP and port the host gives you just as usual.
- You can host and connect to peer with or without using autopunch: no compatibility issues, you can always leave it running.
- **However, if a host didn't forward its ports, both peers will need autopunch, not just the one hosting!**

![](doc/screen.jpg)

### Troubleshooting

- If you experience any issue when using autopunch, make sure that both peers are running autopunch. *For Hisoutensoku players: if using SokuRoll, run it before running the tool.*
- For some very rare users having a very old or cheap Internet router, or playing at a work office, autopunch might just not work *when they are hosting*. Try switching who hosts if this happens.
- If you have any other issue or feedback, either contact me on Discord at `cc#6439` or [open an issue on Github](https://github.com/delthas/autopunch/issues/new). **When doing that, please check the Debug checkbox, punch and play again, close the game and send me the log file.**

## Advanced usage

- No command-line flags, no advanced usage. If you need anything specific open an issue or ask me.

## Building

Quick overview of the components of the project:
- `inject.c`: the core autopunch DLL, that is injected into a game; has both 32 and 64 bit versions, release and debug versions;
- `address`: a tiny program to get the address of the `LoadLibraryW` function of the WoW `Kernel32` module; this works because ASLR is only done once per reboot;
- `packer`: a tiny program to pack a binary file as a string in a Go source file so that it can be included in an executable;
- `relay`: the STUN-like relay used by autopunch;
- `loader`: the program that has the GUI and autoupdates, and starts the injection of the autopunch DLL; the final executable packs the 4 autopunch DLLs, the address executable, and a Win32 app manifest.

**Do not use `go get`. Clone manually.**

Preparation:
- make sure you pulled all submodules;
- install an `i686-w64-mingw32-gcc` toolchain (for example with MSYS2);
- install the Microsoft Visual C++ Build Tools;
- install CMake;
- install Go;
- install https://github.com/akavel/rsrc (and add $GOPATH/bin to PATH if needed).

Build order:
- build `address` with CMake, compiling with `i686-w64-mingw32-gcc`, profile MinSizeRel;
- build `packer` with Go; `go install` it / add it to your PATH;
- build `inject.c` (at the root) with CMake four times: Debug and Release, for Visual C++ Build Tools x86 and x64; use the `autopunch_copy` target to put the DLLs in the right folder for next steps;
- generate `loader` with: `go generate loader.go`;
- build `loader` twice, targeting GOARCH=amd64 then GOARCH=386, GOOS=windows, with: `go build -ldflags="-H windowsgui -s -w -X main.version=<version>" -tags walk_use_cgo`; `version` is e.g. `v0.0.1`.

Building the relay (Go) is straightforward.
