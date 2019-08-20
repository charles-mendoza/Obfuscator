#include <Windows.h>
#include <stdio.h>

#define OBFUSCATE_STRINGS

#include "Obfuscation.h"

using namespace std;

int main()
{
	IFN(LoadLibraryA)(XOR("msvcrt.dll"));
	IFN(LoadLibraryA)(XOR("user32.dll"));

	IFN(printf)(XOR("%s %s\n"), "Not obfuscated", XOR("Obfuscated"));
	IFN(MessageBoxW)(NULL, XORW(L"\u304B\u308F\u3044\u3044\u732B\u597D\u304D"), L"hello world", MB_OK);
	IFN(system)(XOR("pause>nul"));

	return 0;
}