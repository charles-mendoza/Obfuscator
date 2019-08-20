// Copyright (c) 2010-2017, Sebastien Andrivet
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once
#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <stdint.h>
#include <map>

#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__((always_inline))
#endif

namespace Obfuscation
{
	// Implementation of an obfuscated string
	// No limitations:
	// - No truncation
	// - Key generated at compile time
	// - Algorithm selected at compile time (there are three examples below)

	namespace
	{
		// I use current (compile time) as a seed

		constexpr char time[] = __TIME__; // __TIME__ has the following format: hh:mm:ss in 24-hour time

										  // Convert time string (hh:mm:ss) into a number
		constexpr int DigitToInt(char c) { return c - '0'; }
		const int seed = DigitToInt(time[7]) +
			DigitToInt(time[6]) * 10 +
			DigitToInt(time[4]) * 60 +
			DigitToInt(time[3]) * 600 +
			DigitToInt(time[1]) * 3600 +
			DigitToInt(time[0]) * 36000;
	}

	// 1988, Stephen Park and Keith Miller
	// "Random Number Generators: Good Ones Are Hard To Find", considered as "minimal standard"
	// Park-Miller 31 bit pseudo-random number generator, implemented with G. Carta's optimisation:
	// with 32-bit math and without division

	template<int N>
	struct RandomGenerator
	{
	private:
		static constexpr unsigned a = 16807;        // 7^5
		static constexpr unsigned m = 2147483647;   // 2^31 - 1

		static constexpr unsigned s = RandomGenerator<N - 1>::value;
		static constexpr unsigned lo = a * (s & 0xFFFF);                // Multiply lower 16 bits by 16807
		static constexpr unsigned hi = a * (s >> 16);                   // Multiply higher 16 bits by 16807
		static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16);     // Combine lower 15 bits of hi with lo's upper bits
		static constexpr unsigned hi2 = hi >> 15;                       // Discard lower 15 bits of hi
		static constexpr unsigned lo3 = lo2 + hi;

	public:
		static constexpr unsigned max = m;
		static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
	};

	template<>
	struct RandomGenerator<0>
	{
		static constexpr unsigned value = seed;
	};

	// Note: A bias is introduced by the modulo operation.
	// However, I do belive it is neglictable in this case (M is far lower than 2^31 - 1)

	template<int N, int M>
	struct Random
	{
		static const int value = RandomGenerator<N + 1>::value % M;
	};

	// std::index_sequence will be available with C++14 (C++1y). For the moment, implement a (very) simplified and partial version. You can find more complete versions on the Internet
	// MakeIndex<N>::type generates Indexes<0, 1, 2, 3, ..., N>

	template<int... I>
	struct Indexes { using type = Indexes<I..., sizeof...(I)>; };

	template<int N>
	struct Make_Indexes { using type = typename Make_Indexes<N - 1>::type::type; };

	template<>
	struct Make_Indexes<0> { using type = Indexes<>; };

	// Represents an obfuscated string, parametrized with an alrorithm number N, a list of indexes Indexes and a key Key

	template<int N, char Key, typename Indexes>
	struct XorString;

	template<int N, wchar_t Key, typename Indexes>
	struct XorStringW;

	// Partial specialization with a list of indexes I, a key K and algorithm N = 0
	// Each character is encrypted (XOR) with the same key, stored at the beginning of the buffer

	template<char K, int... I>
	struct XorString<0, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is stored as the first element of the buffer
		constexpr ALWAYS_INLINE XorString(const char* str)
			: buffer_{ K, encrypt(str[I])... } { }

		// Runtime decryption. Most of the time, inlined
		inline const char* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i + 1] = decrypt(buffer_[i + 1]);
			buffer_[sizeof...(I)+1] = 0;
			return buffer_ + 1;
		}

	private:
		// Encrypt / decrypt a character of the original string with the key
		constexpr char key() const { return buffer_[0]; }
		constexpr char encrypt(char c) const { return c ^ key(); }
		constexpr char decrypt(char c) const { return encrypt(c); }

		// Buffer to store the encrypted string + terminating null byte + key
		char buffer_[sizeof...(I)+2];
	};

	template<wchar_t K, int... I>
	struct XorStringW<0, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is stored as the first element of the buffer
		constexpr ALWAYS_INLINE XorStringW(const wchar_t* str)
			: buffer_{ K, encrypt(str[I])... } { }

		// Runtime decryption. Most of the time, inlined
		inline const wchar_t* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i + 1] = decrypt(buffer_[i + 1]);
			buffer_[sizeof...(I)+1] = 0;
			return buffer_ + 1;
		}

	private:
		// Encrypt / decrypt a wchar_tacter of the original string with the key
		constexpr wchar_t key() const { return buffer_[0]; }
		constexpr wchar_t encrypt(wchar_t c) const { return c ^ key(); }
		constexpr wchar_t decrypt(wchar_t c) const { return encrypt(c); }

		// Buffer to store the encrypted string + terminating null byte + key
		wchar_t buffer_[sizeof...(I)+2];
	};

	// Partial specialization with a list of indexes I, a key K and algorithm N = 1
	// Each character is encrypted (XOR) with an incremented key. The first key is stored at the beginning of the buffer

	template<char K, int... I>
	struct XorString<1, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is stored as the first element of the buffer
		constexpr ALWAYS_INLINE XorString(const char* str)
			: buffer_{ K, encrypt(str[I], I)... } { }

		// Runtime decryption. Most of the time, inlined
		inline const char* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i + 1] = decrypt(buffer_[i + 1], i);
			buffer_[sizeof...(I)+1] = 0;
			return buffer_ + 1;
		}

	private:
		// Encrypt / decrypt a character of the original string with the key
		constexpr char key(size_t position) const { return static_cast<char>(buffer_[0] + position); }
		constexpr char encrypt(char c, size_t position) const { return c ^ key(position); }
		constexpr char decrypt(char c, size_t position) const { return encrypt(c, position); }

		// Buffer to store the encrypted string + terminating null byte + key
		char buffer_[sizeof...(I)+2];
	};

	template<wchar_t K, int... I>
	struct XorStringW<1, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is stored as the first element of the buffer
		constexpr ALWAYS_INLINE XorStringW(const wchar_t* str)
			: buffer_{ K, encrypt(str[I], I)... } { }

		// Runtime decryption. Most of the time, inlined
		inline const wchar_t* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i + 1] = decrypt(buffer_[i + 1], i);
			buffer_[sizeof...(I)+1] = 0;
			return buffer_ + 1;
		}

	private:
		// Encrypt / decrypt a wchar_tacter of the original string with the key
		constexpr wchar_t key(size_t position) const { return static_cast<wchar_t>(buffer_[0] + position); }
		constexpr wchar_t encrypt(wchar_t c, size_t position) const { return c ^ key(position); }
		constexpr wchar_t decrypt(wchar_t c, size_t position) const { return encrypt(c, position); }

		// Buffer to store the encrypted string + terminating null byte + key
		wchar_t buffer_[sizeof...(I)+2];
	};

	// Partial specialization with a list of indexes I, a key K and algorithm N = 2
	// Shift the value of each character and does not store the key. It is only used at compile-time.

	template<char K, int... I>
	struct XorString<2, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is *not* stored
		constexpr ALWAYS_INLINE XorString(const char* str)
			: buffer_{ encrypt(str[I])..., 0 } { }

		// Runtime decryption. Most of the time, inlined
		inline const char* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i]);
			return buffer_;
		}

	private:
		// Encrypt / decrypt a character of the original string with the key
		constexpr char key(char key) const { return key % 13; }
		constexpr char encrypt(char c) const { return c + key(K); }
		constexpr char decrypt(char c) const { return c - key(K); }

		// Buffer to store the encrypted string + terminating null byte. Key is not stored
		char buffer_[sizeof...(I)+1];
	};

	template<wchar_t K, int... I>
	struct XorStringW<2, K, Indexes<I...>>
	{
		// Constructor. Evaluated at compile time. Key is *not* stored
		constexpr ALWAYS_INLINE XorStringW(const wchar_t* str)
			: buffer_{ encrypt(str[I])..., 0 } { }

		// Runtime decryption. Most of the time, inlined
		inline const wchar_t* decrypt()
		{
			for (size_t i = 0; i < sizeof...(I); ++i)
				buffer_[i] = decrypt(buffer_[i]);
			return buffer_;
		}

	private:
		// Encrypt / decrypt a wchar_tacter of the original string with the key
		constexpr wchar_t key(wchar_t key) const { return key % 13; }
		constexpr wchar_t encrypt(wchar_t c) const { return c + key(K); }
		constexpr wchar_t decrypt(wchar_t c) const { return c - key(K); }

		// Buffer to store the encrypted string + terminating null byte. Key is not stored
		wchar_t buffer_[sizeof...(I)+1];
	};

	// Helper to generate a key
	template<int N>
	struct RandomChar
	{
		// Use 0x7F as maximum value since most of the time, char is signed (we have however 1 bit less of randomness)
		static const char value = static_cast<char>(1 + Random<N, 0x7F - 1>::value);
	};

	template<int N>
	struct RandomCharW
	{
		// Use 0xFFFF as maximum value of wchar_t (we have however 1 bit less of randomness)
		static const wchar_t value = static_cast<wchar_t>(1 + Random<N, 0xFFFF - 1>::value);
	};

	// Compile-time recursive mod of string hashing algorithm, the actual algorithm was taken from Qt library
	constexpr uint32_t HashPart3(char c, uint32_t hash) { return ((hash << 4) + c); }
	constexpr uint32_t HashPart2(char c, uint32_t hash) { return (HashPart3(c, hash) ^ ((HashPart3(c, hash) & 0xF0000000) >> 23)); }
	constexpr uint32_t HashPart1(char c, uint32_t hash) { return (HashPart2(c, hash) & 0x0FFFFFFF); }
	constexpr uint32_t Hash(const char* str) { return (*str) ? (HashPart1(*str, Hash(str + 1))) : (0); }

	constexpr uint32_t HashPart3W(wchar_t c, uint32_t hash) { return ((hash << 4) + c); }
	constexpr uint32_t HashPart2W(wchar_t c, uint32_t hash) { return (HashPart3W(c, hash) ^ ((HashPart3W(c, hash) & 0xF0000000) >> 23)); }
	constexpr uint32_t HashPart1W(wchar_t c, uint32_t hash) { return (HashPart2W(c, hash) & 0x0FFFFFFF); }
	constexpr uint32_t HashW(const wchar_t* str) { return (*str) ? (HashPart1W(*str, HashW(str + 1))) : (0); }

} // Obfuscation

// Prefix notation
#define DEF_XOR(str) Obfuscation::XorString<Obfuscation::Random<__COUNTER__, 3>::value, Obfuscation::RandomChar<__COUNTER__>::value, Obfuscation::Make_Indexes<sizeof(str) - 1>::type>(str)
#define DEF_XORW(str) Obfuscation::XorStringW<Obfuscation::Random<__COUNTER__, 3>::value, Obfuscation::RandomCharW<__COUNTER__>::value, Obfuscation::Make_Indexes<sizeof(str) - 1>::type>(str)

#ifdef OBFUSCATE_STRINGS
#define XOR(str) (DEF_XOR(str).decrypt())
#define XORW(str) (DEF_XORW(str).decrypt())
#else
#define XOR(str) (str)
#define XORW(str) (str)
#endif

// Compile-time hashing macro
#define HASH(str) (uint32_t)(Obfuscation::Hash(str) ^ Obfuscation::Random<0, 0x7FFFFFFF>::value)
#define HASHW(str) (uint32_t)(Obfuscation::HashW(str) ^ Obfuscation::Random<0, 0x7FFFFFFF>::value)

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct LDR_DATA_ENTRY
{
	LIST_ENTRY              InMemoryOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_DATA_ENTRY, *PLDR_DATA_ENTRY;

__declspec(naked) PLDR_DATA_ENTRY GetLdrDataEntry() {
	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax + 0x0C]
		mov eax, [eax + 0x1C]
		retn
	}
}

bool dll_allowed(const wchar_t* dllName)
{
	static const wchar_t* AllowedModules[] =
	{
		L"advapi32.dll",
		L"kernelbase.dll",
		L"kernel32.dll",
		L"mpr.dll",
		L"mscoree.dll",
		L"msvcrt.dll",
		L"ntdll.dll",
		L"user32.dll",
		L"winmm.dll"
	};

	for (auto str : AllowedModules)
	{
		if (_wcsicmp(dllName, str) == 0)
			return true;
	}

	return false;
}

void* GetFuncByHash(uint32_t hash)
{
	static std::map<uint32_t, void*> fnMap;

	if (fnMap[hash])
		return fnMap[hash];

	PLDR_DATA_ENTRY pLDE;
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	HMODULE hModule;
	PDWORD Address, Name;
	PWORD Ordinal;

	for (pLDE = GetLdrDataEntry(); pLDE->BaseAddress; pLDE = (PLDR_DATA_ENTRY)pLDE->InMemoryOrderModuleList.Flink)
	{
		if (!dll_allowed(pLDE->BaseDllName.Buffer)) { continue; }
		hModule = (HMODULE)pLDE->BaseAddress;
		if (!hModule) { continue; }
		pIDH = (PIMAGE_DOS_HEADER)hModule;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) { continue; }
		pINH = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE) { continue; }
		if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) { continue; }

		pIDH = (PIMAGE_DOS_HEADER)hModule;
		pINH = (PIMAGE_NT_HEADERS)((LONG)hModule + pIDH->e_lfanew);
		pIED = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		Address = (PDWORD)((BYTE*)hModule + pIED->AddressOfFunctions);
		Name = (PDWORD)((BYTE*)hModule + pIED->AddressOfNames);
		Ordinal = (PWORD)((BYTE*)hModule + pIED->AddressOfNameOrdinals);

		if (!Address || !Name || !Ordinal)
			continue;

		for (DWORD i = 0; i < pIED->NumberOfFunctions; i++)
		{
			uint32_t fnHash = HASH((char*)hModule + Name[i]);
			fnMap[fnHash] = (void*)((BYTE*)hModule + Address[Ordinal[i]]);

			if (fnHash == hash)
				return fnMap[fnHash];
		}
	}

	return NULL;
}

#define IFN(name) (reinterpret_cast<decltype(&name)>(GetFuncByHash(HASH(#name))))

#endif