# macOS Support (Ghidra Extension)

This is a Ghidra extension that I wrote to better support macOS security research. I use it for my own purposes, but I thought I'd also put it out here in case anyone else finds it useful.

## What does the extension do?

Currently the extension has two parts:

1. A Loader extension that gives loaded Mach-O binaries more friendly names in the project files (and in the Code Editor). Without it, the contents of universal Mach-O binaries will appear in the project directory named only after the architecture and CPU information. This extension will prefix those names with the parent binary name. The program name itself (used to name things such as the Data Type archive in CodeBrowser, among other things), is also similarly changed. **_Note that this is automatic, and not configurable._**
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


## Can I contribute?

Sure! Just note that this really requires the use of the [Eclipse IDE](https://eclipseide.org). I'm not really going to provide much support on how to use Eclipse for Ghidra extension development, other than to point you to official resources.

Developing Ghidra extensions on Eclipse requires GhidraDev, and instructions on how to install GhidraDev into Eclipse are located *within* your installation of Ghidra (at lease on v11.2) at:

```
{Ghidra-Installation-Folder}/Extensions/Eclipse/GhidraDev/GhidraDev_README.html#ManualInstall
```

### Before Running

Ghidra only supports loading built modules from `bin/main` in the project root. Unfortunately, it seems Eclipse defaults to `bin/default`, which will cause this extension to not be loaded by Ghidra when using the Run Configurations provided GhidraDev. To fix this, simply:

1. Right-Click the project in Eclipse to open the context menu.
2. Hover over the "Build Path" item to open the sub-menu and select "Configure Build Path".
3. If not already selected, select the Source tab and change the "Default output folder" to: `{project-name}/bin/main`.

I unfortunately have not found an easy way to distribute this with the project, so (for now) this step has to be done manually.