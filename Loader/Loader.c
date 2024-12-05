#include "Loader.h"
#include <ntimage.h>

BOOLEAN CaseInsensitiveStrstr(PUCHAR haystack, PUCHAR needle) {
	size_t haystackLen = strlen(haystack);
	size_t needleLen = strlen(needle);

	if (needleLen > haystackLen) {
		return FALSE; 
	}

	for (size_t i = 0; i <= haystackLen - needleLen; i++) {
		if (_strnicmp(haystack + i, needle, needleLen) == 0) {
			return TRUE; 
		}
	}
	return FALSE; 
}

// 获取模块地址
ULONG_PTR QueryModule(PUCHAR moduleName) {
	RTL_PROCESS_MODULES rtlModule = { 0 };
	PRTL_PROCESS_MODULES SystemModules = &rtlModule;
	ULONG retLen = 0;

	BOOLEAN isAlloc;
	__try {
		NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, SystemModules, sizeof(RTL_PROCESS_MODULES), &retLen);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			SystemModules = ExAllocatePool(PagedPool, retLen + sizeof(RTL_PROCESS_MODULES));
			memset(SystemModules, 0, retLen + sizeof(RTL_PROCESS_MODULES));

			NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, SystemModules, retLen + sizeof(RTL_PROCESS_MODULES), &retLen);

			if (!NT_SUCCESS(status)) {
				ExFreePool(SystemModules);
				return 0;
			}
		}
	}__except(EXCEPTION_EXECUTE_HANDLER){
		return GetExceptionCode();
	}

		ULONG_PTR moduleBase = 0;
		do {
			if (_stricmp(moduleName, "ntoskrnl.exe") == 0 || _stricmp(moduleName, "ntkrnlpa.exe") == 0) {
				PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &SystemModules->Modules[0];
				moduleBase = ModuleInfo->ImageBase;
				break;
			}


			for (int i = 0; i < SystemModules->NumberOfModules; i++) {

				PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &SystemModules->Modules[i];
				PUCHAR pathName = _strupr(ModuleInfo->FullPathName);
				if (CaseInsensitiveStrstr(pathName, moduleName)) {
					moduleBase = ModuleInfo->ImageBase;
					break;
				}
			}
		} while (0);

		ExFreePool(SystemModules);
	

	return moduleBase;
}
// 获取函数地址
PVOID FindExportedRoutineByName(PVOID moduleBase, PCSTR routineName) {
	if (!moduleBase || !routineName) {
		return NULL;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDosHeader->e_lfanew);
	// 获取导出表
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pExportDir) {
		return NULL;
	}

	// 获取函数名称表、函数地址表和名称序号表
	ULONG* pFunctionAddresses = (ULONG*)((PUCHAR)moduleBase + pExportDir->AddressOfFunctions);
	ULONG* pNameAddresses = (ULONG*)((PUCHAR)moduleBase + pExportDir->AddressOfNames);
	USHORT* pNameOrdinals = (USHORT*)((PUCHAR)moduleBase + pExportDir->AddressOfNameOrdinals);

	// 遍历所有函数名
	for (ULONG i = 0; i < pExportDir->NumberOfNames; i++) {
		PCSTR pFunctionName = (PCSTR)((PUCHAR)moduleBase + pNameAddresses[i]);
		if (_stricmp(pFunctionName, routineName) == 0) {
			// 通过序号获取对应的函数地址
			ULONG funcOrdinal = pNameOrdinals[i];
			ULONG_PTR functionAddress = (ULONG_PTR)((PUCHAR)moduleBase + pFunctionAddresses[funcOrdinal]);

			return (PVOID)functionAddress;
		}
	}
	return NULL;
}

PUCHAR FileToImage(char* fileBuf) {
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + fileBuf);
	
	ULONG sectionNum = pNtHeader->FileHeader.NumberOfSections;
	ULONG sizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;

	PUCHAR ImageBuf = ExAllocatePool(NonPagedPool, sizeOfImage);
	memset(ImageBuf, 0, sizeOfImage);

	RtlCopyMemory(ImageBuf, fileBuf, pNtHeader->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (ULONG i=0 ; i<sectionNum;i++){
		RtlCopyMemory(ImageBuf + pSection->VirtualAddress, fileBuf + pSection->PointerToRawData, pSection->SizeOfRawData);

		pSection++;
	}

	ULONG relocationRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	ULONG relocationSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(ImageBuf + relocationRVA);

	while (pRelocation->SizeOfBlock && pRelocation->VirtualAddress){
		ULONG PageVA = pRelocation->VirtualAddress; 
		ULONG BlockSize = pRelocation->SizeOfBlock;

		ULONG EntryCount = (BlockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		PUSHORT RelocData = (PUSHORT)((PUCHAR)pRelocation + sizeof(IMAGE_BASE_RELOCATION));
		for (ULONG i = 0; i < EntryCount; i++) {
			USHORT RelocEntry = RelocData[i];
			USHORT Type = (RelocEntry >> 12);  // 高 4 位是类型
			USHORT Offset = (RelocEntry & 0xFFF);  // 低 12 位是偏移

			if (Type == IMAGE_REL_BASED_HIGHLOW) {
				// 32 位地址重定位
				PULONG pPatch = (PULONG)((PUCHAR)ImageBuf + PageVA + Offset);
				ULONG OriginalBaseAddress = pNtHeader->OptionalHeader.ImageBase;
				*pPatch += (ULONG)((ULONG_PTR)ImageBuf - OriginalBaseAddress);
			}
			else if (Type == IMAGE_REL_BASED_DIR64) {
				// 64 位地址重定位
				PULONGLONG pPatch = (PULONGLONG)((PUCHAR)ImageBuf + PageVA + Offset);
				ULONGLONG OriginalBaseAddress = pNtHeader->OptionalHeader.ImageBase;
				*pPatch += ((ULONG_PTR)ImageBuf - OriginalBaseAddress);
			}
		}

		pRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocation + BlockSize);

	}
	
	PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pImportDir->VirtualAddress + ImageBuf);
	while (pImport->Name){

		PUCHAR libName = (PUCHAR)(ImageBuf + pImport->Name);
		ULONG_PTR base = QueryModule(libName);

		PIMAGE_THUNK_DATA pThunkName = (PIMAGE_THUNK_DATA)(ImageBuf + pImport->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunkFunc = (PIMAGE_THUNK_DATA)(ImageBuf + pImport->FirstThunk);
		
		while (pThunkName->u1.ForwarderString) {
			PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)(ImageBuf + pThunkName->u1.AddressOfData);
			ULONG_PTR funcAddress = FindExportedRoutineByName(base, FuncName->Name);
			if (funcAddress) {
				pThunkFunc->u1.Function = (ULONG_PTR)funcAddress;
			}
			pThunkName++;
			pThunkFunc++;
		}


		pImport++;
	}

	// 修复cookie
	PIMAGE_DATA_DIRECTORY pConfigDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	PIMAGE_LOAD_CONFIG_DIRECTORY config = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pConfigDir->VirtualAddress + ImageBuf);

	
	*(PULONG_PTR)(config->SecurityCookie) += 10;


	return ImageBuf;
}


BOOLEAN loadDriver(PUCHAR fileBuf) {
	PUCHAR ImageBuf = FileToImage(fileBuf);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + ImageBuf);
	DWORD_PTR entry = pNtHeader->OptionalHeader.AddressOfEntryPoint + ImageBuf;
	DriverEntrypProc EntrypProc = (DriverEntrypProc)entry;
	__try {
		EntrypProc(NULL, NULL);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExFreePool(ImageBuf);
		DbgPrint("0x%x\n", GetExceptionCode());
		return GetExceptionCode();
	}
	
}