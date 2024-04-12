# re-scripts
Ghidra and IDA scripts that I use but that aren't polished enough for general usage. Sharing in hopes that someone will potentially find these useful and adapt these for their own usage. Made for reverse engineering the popular 2D platformer game: Geometry Dash.

If you intend on using these, make sure to look inside first, a lot of these have hardcoded filesystem paths and what not.

More polished scripts are moved to the [Geode Bindings repository](https://github.com/geode-sdk/bindings/tree/main/scripts/ghidra).

## ExportVirtualsScript.java && ImportVirtualsScript.java
This is a pair of scripts that exports Virtuals from a binary with matching class layouts (in this instance a Geode mod) and imports them into another binary (in this case the Geometry Dash game).

Pre-requisites (for Geode):
- add inlined dtors for all funcs that are currently missing them in the bindings
- build a mod in relwithdebinfo (not debug!)
- it must be built with msvc (not clang!)

## ExportVirtualsAndroidScript.java && ImportVirtualsMacScript.java
Since both Android and Mac use Itanium ABI, we can safely assume the vtables for the 2 platforms are identical, given that we have the same version of the game. That is what this pair of scripts does.

## FindEmptyVirtualsScript.java
This one is next to unusable, it only prints function names for a given list of addresses. Kinda useful, since empty functions are all merged into one or few addresses on Windows, but for this purpose it'd be better to use Android and just analyze which functions only consist of a single ret instruction or something similar.
