// Yes i used ChatGPT but who cares as long as i learned with it

#include <iostream> // For user prompt and console output
#include <Windows.h> // OS functions
#include <Psapi.h> // To get process info
#include <string>
#include <tlhelp32.h>
#include <unordered_map>
#include <thread>
//#include "F:/AppSrc/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.38.33130/include/xstring"
//#include "F:/AppSrc/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.38.33130/include/vadefs.h"
//#include "F:/AppSrc/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.38.33130/include/string"
using namespace std;

#define LOG(msg) std::cout << msg << std::endl
#define ASK(msg) std::cout << msg

using namespace std;

// addr.r(1568A0): Address of UserDefault

// Function to rebase the address using the base address of dll "cocos2d-win10.dll"

uintptr_t GetModuleBaseAddress(DWORD processId, const wchar_t* moduleName)
{
	uintptr_t baseAddress = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(snapshot, &moduleEntry))
		{
			do
			{
				if (_wcsicmp(moduleEntry.szModule, moduleName) == 0)
				{
					baseAddress = (uintptr_t)moduleEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(snapshot, &moduleEntry));
		}

		CloseHandle(snapshot);
	}

	return baseAddress;
}

DWORD GetPIDByName(const wchar_t* processName) {
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &processEntry)) {
		do {
			if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
				CloseHandle(snapshot);
				return processEntry.th32ProcessID;
			}
		} while (Process32Next(snapshot, &processEntry));
	}

	CloseHandle(snapshot);
	return 0; // Return 0 if the process is not found
}

DWORD GetBaseAddress(const HANDLE hProcess) {
	if (hProcess == NULL)
		return NULL; // No access to the process

	HMODULE lphModule[1024]; // Array that receives the list of module handles
	DWORD lpcbNeeded(NULL); // Output of EnumProcessModules, giving the number of bytes requires to store all modules handles in the lphModule array

	if (!EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &lpcbNeeded))
		return NULL; // Impossible to read modules

	TCHAR szModName[MAX_PATH];
	if (!GetModuleFileNameEx(hProcess, lphModule[0], szModName, sizeof(szModName) / sizeof(TCHAR)))
		return NULL; // Impossible to get module info

	return (DWORD)lphModule[0]; // Module 0 is apparently always the EXE itself, returning its address
}

long long convertToLongLong(const std::string& input) {
	try {
		return std::stoll(input);
	}
	catch (const std::out_of_range& e) {
		// Handle out-of-range error
		throw std::out_of_range("Input number is too large for long long.");
	}
	catch (const std::invalid_argument& e) {
		// Handle invalid argument error
		throw std::invalid_argument("Invalid input. Please enter a valid number.");
	}
}

void godmode(HANDLE hProcess, LPVOID targetAddress, BYTE newOpcode, BYTE& originalOpcode) {
		DWORD oldProtect;
		VirtualProtectEx(hProcess, targetAddress, 1, PAGE_EXECUTE_READWRITE, & oldProtect);
		WriteProcessMemory(hProcess, targetAddress, &newOpcode, sizeof(newOpcode), NULL);
		VirtualProtectEx(hProcess, targetAddress, 1, oldProtect, &oldProtect);
}

class address {
public:
	address() : offsets{
		{ "coins", 0x28CAD4 },
		{ "gems", 0x28CAEC },
		{ "fuel", 0x28CA2C },
		{ "fuel_offset", 0x2A8 },
		{ "godmode", 0xDBAE0 },
		{ "godmode_boolean", 0x28CA2C },
		{ "godmode_boolean_offset_1", 0x184 },
		{ "godmode_boolean_offset_2", 0x14C},
		{ "godmode_boolean_offset_3", 0x74 },
		{ "infBoostAddr", 0x459D3 }
	} {}

	int getOffset(const string& offsetName) {
		return offsets[offsetName];
	}


	HANDLE cocos2dDLL;
	int BaseAddress;
	HANDLE hProcess;

	int r(const string& offsetName) {
		return (BaseAddress + offsets[offsetName]);
	}

	int editMemFromOffset(const string& offsetName, int newValue) {
		return WriteProcessMemory(hProcess, (LPVOID)r(offsetName), &newValue, sizeof(newValue), NULL);
	}

	int editMemFromAddress(const uintptr_t address, int newValue) {
		return WriteProcessMemory(hProcess, (LPVOID)address, &newValue, sizeof(newValue), NULL);
	}

	int readMemFromOffset(const string& offsetName) {
		int value;
		ReadProcessMemory(hProcess, (LPVOID)r(offsetName), &value, sizeof(value), NULL);
		return value;
	}

	void freezeValue(const uintptr_t address, int value) {
		while (true) {
			editMemFromAddress(address, value);
			this_thread::sleep_for(chrono::milliseconds(100));
		}
	}

	int readMemFromAddress(const uintptr_t address) {
		int value;
		ReadProcessMemory(hProcess, (LPVOID)address, &value, sizeof(value), NULL);
		return value;
	}

	int calcPointerChain(const string& baseOffsetName, const vector<string>& offsetNames) {
		uintptr_t currentAddress = r(baseOffsetName);

		for (const auto& offsetName : offsetNames) {
			currentAddress = readMemFromAddress(currentAddress) + getOffset(offsetName);
		}

		// Read and return the value at the final address
		return currentAddress;
	}

private:
	std::unordered_map<string, intptr_t> offsets;
};

int main() {
	DWORD HCRpid = GetPIDByName(L"HillClimbRacing.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, HCRpid);
	address addr;
	addr.cocos2dDLL = (HANDLE)GetModuleBaseAddress(HCRpid, L"cocos2d-win10.dll");
	addr.hProcess = hProcess;
	addr.BaseAddress = GetBaseAddress(hProcess);
	LOG("Found cocos2d-win10.dll base address: " << hex << addr.cocos2dDLL);
	LOG("Found HillClimbRacing.exe base address: " << std::hex << addr.BaseAddress);
	cout << "BaseAddress + 0028CA2C:" << hex << addr.BaseAddress + 0x0028CA2C << endl;
	//godmode variables
	bool godModeEnabled = false;
	bool InfBoostEnabled = false;
	BYTE originalInfBoostOpcode = addr.readMemFromOffset("infBoostAddr");
	BYTE originalGMOpcode = addr.readMemFromOffset("godmode");
	while (true) {
		ASK("1. Edit coins (MAX 2147483647)\n2. Edit gems (MAX 2147483647)\n3. Unlimited fuel\n4. GodMode (" << (godModeEnabled ? "ENABLED" : "DISABLED") << ")\n5. Infinite Boosts (" << (InfBoostEnabled ? "ENABLED" : "DISABLED") << ")\nEnter option(NUMBER) : ");
		string input;
		long long newValue;
		long long selection = convertToLongLong(cin >> input ? input : "999999999");
		switch (selection)
		{
			case 1:
				ASK("Enter new value: ");
				newValue = convertToLongLong(cin >> input ? input : "999999999");
				addr.editMemFromOffset("coins", newValue);
				break;
			case 2:
				ASK("Enter new value: ");
				newValue = convertToLongLong(cin >> input ? input : "999999999");
				addr.editMemFromOffset("gems", newValue);
				break;
			case 3:
			{
				thread freezeFuel(&address::freezeValue, addr, (uintptr_t)addr.calcPointerChain("fuel", { "fuel_offset" }), 1120481605);
				freezeFuel.detach();
				break;
			}
				
			case 4:
				if (godModeEnabled) {
					int GodMode = addr.calcPointerChain("godmode_boolean", { "godmode_boolean_offset_1", "godmode_boolean_offset_2", "godmode_boolean_offset_3" });
					cout << "GodMode: " << GodMode << endl;
					cout << originalGMOpcode << endl;
					addr.editMemFromAddress(GodMode, 0);
					// addr.editMemFromAddress((uintptr_t)addr.readMemFromOffset("godmode_boolean") + addr.getOffset("godmode_boolean_offsets"), 0);
					godmode(hProcess, (LPVOID)addr.r("godmode"), 0x57, originalGMOpcode);
					godModeEnabled = false;
					}
				else {
					godmode(hProcess, (LPVOID)addr.r("godmode"), 0xC3, originalGMOpcode);
					godModeEnabled = true;
					}
				break;
			case 5:
				if (InfBoostEnabled) {
					// addr.editMemFromAddress((uintptr_t)addr.readMemFromOffset("godmode_boolean") + addr.getOffset("godmode_boolean_offsets"), 0);
					godmode(hProcess, (LPVOID)addr.r("InfBoostAddr"), 0x57, originalInfBoostOpcode);
					godModeEnabled = false;
				}
				else {
					godmode(hProcess, (LPVOID)addr.r("InfBoostAddr"), 0xC3, originalInfBoostOpcode);
					InfBoostEnabled = true;
				}
			default:
				break;
		}
	}

	system("pause");
	return EXIT_SUCCESS;
}
