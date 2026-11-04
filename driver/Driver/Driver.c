#include <ntifs.h>
#include <wdf.h>
#include <initguid.h>
#include "RegistryGuard.h"
#include "Match.h"
DEFINE_GUID(GUID_GUARD,0x6cd00f54,0x5dee,0x46dc,0x9d,0x53,0xa8,0x91,0x6d,0x1a,0x13,0x15);
C_ASSERT(sizeof(RG_EVENT)==1088);
typedef struct GUARD_CONTEXT {
 EX_PUSH_LOCK lock;WDFFILEOBJECT owner;PEPROCESS process;
 RG_POLICY policy;RG_STATS stats;RG_U32 head,count;
 RG_EVENT ring[RG_RING],scratch;BOOLEAN registered,cleaned;
 LARGE_INTEGER cookie;
} GUARD_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(GUARD_CONTEXT,Context);
static GUARD_CONTEXT* volatile g_context;
static volatile LONG claimed;
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD AddDevice;
EVT_WDF_OBJECT_CONTEXT_CLEANUP CleanupDevice;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT InitIo;
EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP CleanupIo;
EVT_WDF_DEVICE_FILE_CREATE FileCreate;
EVT_WDF_FILE_CLEANUP FileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL Control;
static VOID RegistryGuardLock(GUARD_CONTEXT* c){KeEnterCriticalRegion();ExAcquirePushLockExclusive(&c->lock);}
static VOID RegistryGuardUnlock(GUARD_CONTEXT* c){ExReleasePushLockExclusive(&c->lock);KeLeaveCriticalRegion();}
static VOID EmitLocked(GUARD_CONTEXT* c,RG_EVENT* e){
 e->Sequence=++c->stats.Produced;e->Generation=c->stats.Generation;
 if(e->Decision)++c->stats.Denied;if(e->Flags&RG_UNKNOWN_NAME)++c->stats.UnknownNames;
 if(c->count==RG_RING){c->head=(c->head+1)%RG_RING;--c->count;++c->stats.Dropped;}
 c->ring[(c->head+c->count)%RG_RING]=*e;++c->count;
}
static VOID Name(RG_EVENT* e,PCUNICODE_STRING name){
 RG_U32 chars;
 if(!name||!name->Buffer||(name->Length&1)||!name->Length){e->Flags|=RG_UNKNOWN_NAME;return;}
 chars=name->Length/sizeof(WCHAR);if(chars>=RG_PATH){chars=RG_PATH-1;e->Flags|=RG_TRUNCATED;}
 if(chars&&name->Buffer[chars-1]>=0xD800&&name->Buffer[chars-1]<=0xDBFF)--chars;
 RtlCopyMemory(e->Path,name->Buffer,chars*sizeof(WCHAR));e->Chars=chars;
}
static EX_CALLBACK_FUNCTION Notify;
_Use_decl_annotations_ static NTSTATUS Notify(PVOID unused,PVOID argument1,PVOID argument2){
 GUARD_CONTEXT* c=(GUARD_CONTEXT*)InterlockedCompareExchangePointer((PVOID volatile*)&g_context,NULL,NULL);
 REG_NOTIFY_CLASS kind=(REG_NOTIFY_CLASS)(ULONG_PTR)argument1;PVOID object=NULL;PCUNICODE_STRING name=NULL;RG_EVENT* e;RG_U32 i,decision=0;BOOLEAN known;
 UNREFERENCED_PARAMETER(unused);
 if(!c||ExGetPreviousMode()!=UserMode||KeGetCurrentIrql()>APC_LEVEL)return STATUS_SUCCESS;
 switch(kind){
 case RegNtPreSetValueKey:object=((PREG_SET_VALUE_KEY_INFORMATION)argument2)->Object;break;
 case RegNtPreDeleteValueKey:object=((PREG_DELETE_VALUE_KEY_INFORMATION)argument2)->Object;break;
 case RegNtPreDeleteKey:object=((PREG_DELETE_KEY_INFORMATION)argument2)->Object;break;
 case RegNtPreRenameKey:object=((PREG_RENAME_KEY_INFORMATION)argument2)->Object;break;
 default:return STATUS_SUCCESS;
 }
 // Never inspect value contents, user buffers, or invalid pre-open/create objects.
 if(!object)return STATUS_SUCCESS;
 RegistryGuardLock(c);i=c->stats.Active&&!c->cleaned;RegistryGuardUnlock(c);if(!i)return STATUS_SUCCESS;
 known=NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&c->cookie,object,NULL,&name,0));
 RegistryGuardLock(c);
 if(c->stats.Active&&!c->cleaned){
  e=&c->scratch;RtlZeroMemory(e,sizeof(*e));e->Qpc=(RG_U64)KeQueryPerformanceCounter(NULL).QuadPart;e->ProcessId=HandleToULong(PsGetCurrentProcessId());e->ProcessKey=PsGetProcessStartKey(PsGetCurrentProcess());
  e->Operation=kind==RegNtPreSetValueKey?1:kind==RegNtPreDeleteValueKey?2:kind==RegNtPreDeleteKey?3:4;
  if(known)Name(e,name);else e->Flags|=RG_UNKNOWN_NAME;
  if(!(e->Flags&(RG_UNKNOWN_NAME|RG_TRUNCATED)))for(i=0;i<c->policy.Count;++i){RG_RULE* r=&c->policy.Rules[i];
   // Deleting/renaming an ancestor can move the protected subtree as well.
   if(Match(r,e->Path,e->Chars,TRUE)||((e->Operation==3||e->Operation==4)&&Ancestor(r,e->Path,e->Chars))){e->RuleId=r->Id;e->Decision=r->Action;break;}
  }
  // Log only matched operations and unresolvable names; no global registry feed.
  decision=e->Decision;if(e->RuleId||(e->Flags&RG_UNKNOWN_NAME)){e->Status=e->Decision?(RG_U32)STATUS_ACCESS_DENIED:0;EmitLocked(c,e);}
 }RegistryGuardUnlock(c);
 if(name)CmCallbackReleaseKeyObjectIDEx(name);return decision?STATUS_ACCESS_DENIED:STATUS_SUCCESS;
}
VOID FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file){
 GUARD_CONTEXT* c=Context(device);PEPROCESS process=NULL;NTSTATUS status;
 status=PsLookupProcessByProcessId(ULongToHandle(WdfRequestGetRequestorProcessId(request)),&process);
 if(NT_SUCCESS(status)){
  RegistryGuardLock(c);
  if(c->cleaned)status=STATUS_DELETE_PENDING;else if(c->owner)status=STATUS_SHARING_VIOLATION;else {c->owner=file;c->process=process;process=NULL;}
  RegistryGuardUnlock(c);if(process)ObDereferenceObject(process);
 }WdfRequestComplete(request,status);
}
VOID FileCleanup(WDFFILEOBJECT file){
 GUARD_CONTEXT* c=Context(WdfFileObjectGetDevice(file));PEPROCESS process=NULL;
 RegistryGuardLock(c);
 if(c->owner==file){c->stats.Active=0;c->stats.RuleCount=0;RtlZeroMemory(&c->policy,sizeof(c->policy));c->owner=NULL;process=c->process;c->process=NULL;c->head=c->count=0;}
 RegistryGuardUnlock(c);if(process)ObDereferenceObject(process);
}
VOID Control(WDFQUEUE queue,WDFREQUEST request,size_t output,size_t input,ULONG code){
 GUARD_CONTEXT* c=Context(WdfIoQueueGetDevice(queue));PVOID in=NULL,out=NULL;NTSTATUS status=STATUS_SUCCESS;ULONG_PTR written=0;RG_U32 i;
 if(code!=RG_SET&&code!=RG_STOP&&code!=RG_STATUS&&code!=RG_RECEIVE){WdfRequestComplete(request,STATUS_INVALID_DEVICE_REQUEST);return;}
 if(input!=(code==RG_SET?sizeof(RG_POLICY):sizeof(RG_REQUEST))||output!=(code==RG_STATUS?sizeof(RG_STATS):code==RG_RECEIVE?sizeof(RG_BATCH):0)){WdfRequestComplete(request,STATUS_INFO_LENGTH_MISMATCH);return;}
 status=WdfRequestRetrieveInputBuffer(request,input,&in,NULL);if(!NT_SUCCESS(status)){WdfRequestComplete(request,status);return;}
 if(code==RG_SET){
  RG_POLICY* p=in;if(!RG_ValidPolicy(p)){WdfRequestComplete(request,STATUS_INVALID_PARAMETER);return;}
  for(i=0;i<p->Count;++i)if(!AllowedScope(&p->Rules[i])){WdfRequestComplete(request,STATUS_INVALID_PARAMETER);return;}
 }else{RG_REQUEST* r=in;if(r->Version!=RG_VERSION||r->Size!=sizeof(*r)||r->Reserved[0]||r->Reserved[1]){WdfRequestComplete(request,STATUS_INVALID_PARAMETER);return;}}
 if(output){status=WdfRequestRetrieveOutputBuffer(request,output,&out,NULL);if(!NT_SUCCESS(status)){WdfRequestComplete(request,status);return;}}
 RegistryGuardLock(c);
 if(c->cleaned)status=STATUS_DELETE_PENDING;
 else if(c->owner!=WdfRequestGetFileObject(request)||!c->process)status=STATUS_ACCESS_DENIED;
 else if(code==RG_SET){
  c->policy=*(RG_POLICY*)in;c->stats.Active=1;c->stats.RuleCount=c->policy.Count;++c->stats.Generation;
 }else if(code==RG_STOP){c->stats.Active=0;c->stats.RuleCount=0;RtlZeroMemory(&c->policy,sizeof(c->policy));}
 else if(code==RG_STATUS){*(RG_STATS*)out=c->stats;((RG_STATS*)out)->Available=c->count;written=sizeof(RG_STATS);}
 else{RG_BATCH* b=out;RtlZeroMemory(b,sizeof(*b));b->Count=c->count<RG_READ?c->count:RG_READ;
  for(i=0;i<b->Count;++i){b->Events[i]=c->ring[c->head];c->head=(c->head+1)%RG_RING;}c->count-=b->Count;b->Stats=c->stats;b->Stats.Available=c->count;written=sizeof(*b);
 }RegistryGuardUnlock(c);WdfRequestCompleteWithInformation(request,status,written);
}
VOID CleanupDevice(WDFOBJECT object){UNREFERENCED_PARAMETER(object);InterlockedExchange(&claimed,0);}
_Use_decl_annotations_ VOID CleanupIo(WDFDEVICE device){
 GUARD_CONTEXT* c=Context(device);RegistryGuardLock(c);c->cleaned=TRUE;c->stats.Active=0;RegistryGuardUnlock(c);
 // The documented unregister waits for callbacks before context destruction.
 if(c->registered){CmUnRegisterCallback(c->cookie);c->registered=FALSE;}
 InterlockedCompareExchangePointer((PVOID volatile*)&g_context,NULL,c);
}
_Use_decl_annotations_ NTSTATUS InitIo(WDFDEVICE device){
 GUARD_CONTEXT* c=Context(device);NTSTATUS status;
 InterlockedExchangePointer((PVOID volatile*)&g_context,c);
 UNICODE_STRING altitude;
#include "Altitude.h"
 RtlInitUnicodeString(&altitude,GUARD_ALTITUDE);if(!altitude.Length){InterlockedCompareExchangePointer((PVOID volatile*)&g_context,NULL,c);return STATUS_NOT_SUPPORTED;}status=CmRegisterCallbackEx(Notify,&altitude,WdfDriverWdmGetDriverObject(WdfDeviceGetDriver(device)),NULL,&c->cookie,NULL);
 if(!NT_SUCCESS(status)){InterlockedCompareExchangePointer((PVOID volatile*)&g_context,NULL,c);return status;}
 c->registered=TRUE;return STATUS_SUCCESS;
}
NTSTATUS AddDevice(WDFDRIVER driver,PWDFDEVICE_INIT init){
 WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_FILEOBJECT_CONFIG files;WDF_IO_QUEUE_CONFIG queue;WDF_PNPPOWER_EVENT_CALLBACKS pnp;GUARD_CONTEXT* c;NTSTATUS status;UNICODE_STRING sddl;LARGE_INTEGER frequency;
 UNREFERENCED_PARAMETER(driver);if(InterlockedCompareExchange(&claimed,1,0))return STATUS_DEVICE_BUSY;
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);pnp.EvtDeviceSelfManagedIoInit=InitIo;pnp.EvtDeviceSelfManagedIoCleanup=CleanupIo;WdfDeviceInitSetPnpPowerEventCallbacks(init,&pnp);
 WdfDeviceInitSetDeviceType(init,0x8000);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN|FILE_AUTOGENERATED_DEVICE_NAME,FALSE);
 RtlInitUnicodeString(&sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");status=WdfDeviceInitAssignSDDLString(init,&sddl);if(!NT_SUCCESS(status)){InterlockedExchange(&claimed,0);return status;}
 WDF_FILEOBJECT_CONFIG_INIT(&files,FileCreate,NULL,FileCleanup);WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;WdfDeviceInitSetFileObjectConfig(init,&files,&attr);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr,GUARD_CONTEXT);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.EvtCleanupCallback=CleanupDevice;
 status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status)){InterlockedExchange(&claimed,0);return status;}
 c=Context(device);c->stats.Version=RG_VERSION;c->stats.Size=sizeof(RG_STATS);c->stats.Capacity=RG_RING;KeQueryPerformanceCounter(&frequency);c->stats.Frequency=(RG_U64)frequency.QuadPart;
 ExInitializePushLock(&c->lock);
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.EvtIoDeviceControl=Control;queue.PowerManaged=WdfFalse;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,WDF_NO_HANDLE);if(!NT_SUCCESS(status))return status;
 return WdfDeviceCreateDeviceInterface(device,&GUID_GUARD,NULL);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING registry){WDF_DRIVER_CONFIG config;WDF_DRIVER_CONFIG_INIT(&config,AddDevice);return WdfDriverCreate(object,registry,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);}
