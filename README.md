# Obfuscator
This is an obfuscator demonstrating how to use C++11/14 to generate, at compile time, obfuscated code without modifying the compiler or using any external obfuscation tools. It obfuscates strings and calls to functions. Based on the [ADVobfuscator](https://github.com/andrivet/ADVobfuscator).

## Installing
Just include Obfuscation.h and obfuscate all the way!

## Examples
Obfuscate strings:
```cpp
#define OBFUSCATE_STRINGS // to enable string obfuscation
include "Obfuscation.h"
...
XOR("This is an obfuscated string");
XORW(L"This is an obfuscated wide string");
```
Obfuscate function calls:
```cpp
IFN(LoadLibraryA)("user32.dll"); // load the DLL where the MessageBoxA function is located
IFN(MessageBoxA)(NULL, "Hello World!", "Info", MB_OK); // make obfuscated function call
```

## How it Works
The fundamentals of string obfuscation is discussed [here](https://github.com/andrivet/ADVobfuscator). As for the obfuscated function call, basically, the approach is to use an indirect function call so that the address must be computed first and then called. The address of the function is hashed at compile-time. The hashed address is then compared to the hash map of functions from the imported modules of our program. If the hashes match, we invoke the function in that module.

How the hashes of functions from other modules are stored? A hash map of functions from the allowed modules are computed. We only limit a certain number of common imported modules to reduce unnecessary hashed functions that aren't commonly used and also to reduce the slowness of computing the hashes and tabulating them in our hash map.
