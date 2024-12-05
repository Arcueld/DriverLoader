#include <ntifs.h>    
#include "Loader.h"
#include "data.h"



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath){

    
    PUCHAR pMem = NULL;
    pMem = ExAllocatePool(NonPagedPool, sizeof(rawData));
    RtlCopyMemory(pMem, rawData, sizeof(rawData));
    
    
    loadDriver(pMem);

    ExFreePool(pMem);

    return STATUS_UNSUCCESSFUL;
}