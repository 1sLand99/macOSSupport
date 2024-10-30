# macOS Support (Ghidra Extension)

This is a Ghidra extension that I wrote to better support macOS security research. I use it for my own purposes, but I thought I'd also put it out here in case anyone else finds it useful.

## What does the extension do?

Currently the extension has two parts:

1. A Loader extension that gives loaded Mach-O binaries more friendly names in the project files (and in the Code Editor). Without it, the contents universal Mach-O binaries will appear in the project directory named only after the architecture and CPU information. This extension will prefix those names with the parent binary name. The program name itself (used to name things such as the Data Type archive in CodeBrowser, among other things), is also similarly changed. **_Note that this is automatic, and not configurable._**
2. An analysis pass that renames functions that only call `objc_msgSend` after the selector used (in addition to a user-supplied prefix). Many of the ARM programs inside a Mach-O universal binary include functions which only call `objc_msgSend`, essentially "stubbing out" these calls. To make navigating through the code in CodeBrowser easier, this extension includes an analyzer called "Rename objc_msgSend stubs" which will rename these functions after the selector used, prefixed with a configurable prefix (by default the prefix is `objc_msgSend_`). ***Note that this method uses a very strict fingerprint-matching function and may not catch all of the "stubs".***

## Why does the extension do these things?

I wrote this extension to handle two of the things I find myself doing often in Ghidra when working on macOS binaries. This extension helps me work faster and focus more time on reverse engineering instead of renaming things.

## Will there be consistent updates?

Probably not. This repository is really just a dumping ground for my extension and any updates will only be included as I see fit for my uses.

## Can I use this extension?

Of course! Feel free to use this extension however you want. To install it:

1. Download a ZIP (*not* the Source code ZIP, but the other one) from [the Releases section](https://github.com/nmggithub/macOSSupport/releases)
2. Open Ghidra
3. Go to File -> Install Extensions
4. Click the green + (plus) icon
5. Navigate to the ZIP file and select it
6. Click OK
7. Close and reopen Ghidra as prompted