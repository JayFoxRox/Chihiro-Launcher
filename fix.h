// This is meant to fix bugs in the OXDK..

// SEEK_END only goes backwards, not to the end of file..
int __fseek(FILE *stream, long offset, int whence) {
  int fd = fileno(stream);
  if (whence == SEEK_END) { 
    int size;
		XGetFileSize(fd, &size);
    return XSetFilePointer(fd,size+offset,NULL,FILE_CURRENT);
  } else {
    return XSetFilePointer(fd,offset,NULL,(whence==SEEK_CUR)?FILE_CURRENT:FILE_BEGIN);
  }
}
#define fseek(stream,offset,whence) __fseek(stream,offset,whence)

// Doesn't work, didn't check why
long __ftell(FILE *stream) {
  int l;
  XSetFilePointer(fileno(stream), 0, &l, FILE_CURRENT);
  return (long)l;
}
#define ftell(stream) __ftell(stream)

// Doesn't work, didn't check why
size_t __fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  unsigned int bytes;
  XReadFile(fileno(stream),ptr,size*nmemb,&bytes);
  return bytes/size; 
}
#define fread(ptr,size,nmemb,stream) __fread(ptr,size,nmemb,stream)

/*
// Import didn't exist
XBSYSAPI EXPORTNUM(68) VOID IoDeleteDevice(
    IN PDEVICE_OBJECT DeviceObject
);

XBSYSAPI EXPORTNUM(247) NTSTATUS ObReferenceObjectByName(
    IN POBJECT_STRING ObjectName,
    IN ULONG Attributes,
    IN POBJECT_TYPE ObjectType,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID *ReturnedObject
);
*/

typedef struct _XBOX_KRNL_VERSION {
    USHORT Major;
    USHORT Minor;
    USHORT Build;
    USHORT Qfe;
} XBOX_KRNL_VERSION, *PXBOX_KRNL_VERSION;

// http://www.nirsoft.net/kernel_struct/vista/KTRAP_FRAME.html
typedef struct _KTRAP_FRAME {
     ULONG DbgEbp;
     ULONG DbgEip;
     ULONG DbgArgMark;
     ULONG DbgArgPointer;
     WORD TempSegCs;
     UCHAR Logging;
     UCHAR Reserved;
     ULONG TempEsp;
     ULONG Dr0;
     ULONG Dr1;
     ULONG Dr2;
     ULONG Dr3;
     ULONG Dr6;
     ULONG Dr7;
     ULONG SegGs;
     ULONG SegEs;
     ULONG SegDs;
     ULONG Edx;
     ULONG Ecx;
     ULONG Eax;
     ULONG PreviousPreviousMode;
      void* el; //     PEXCEPTION_REGISTRATION_RECORD ExceptionList;
     ULONG SegFs;
     ULONG Edi;
     ULONG Esi;
     ULONG Ebx;
     ULONG Ebp;
     ULONG ErrCode;
     ULONG Eip;
     ULONG SegCs;
     ULONG EFlags;
     ULONG HardwareEsp;
     ULONG HardwareSegSs;
} KTRAP_FRAME;

//http://msdn.microsoft.com/en-us/library/windows/desktop/aa363082%28v=vs.85%29.aspx
#define EXCEPTION_MAXIMUM_PARAMETERS 15
typedef struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD  *ExceptionRecord;
  PVOID                    ExceptionAddress;
  DWORD                    NumberParameters;
  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;


typedef KTRAP_FRAME *PKTRAP_FRAME;



#define MAXIMUM_SUPPORTED_EXTENSION     512
#define SIZE_OF_FX_REGISTERS        128
typedef struct _FLOATING_SAVE_AREA {
    WORD    ControlWord;
    WORD    StatusWord;
    WORD    TagWord;
    WORD    ErrorOpcode;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    DWORD   MXCsr;
    DWORD   Reserved2;
    BYTE    RegisterArea[SIZE_OF_FX_REGISTERS];
    BYTE    XmmRegisterArea[SIZE_OF_FX_REGISTERS];
    BYTE    Reserved4[224];
    DWORD   Cr0NpxState;
} __attribute__((packed)) FLOATING_SAVE_AREA;


typedef FLOATING_SAVE_AREA *PFLOATING_SAVE_AREA;


typedef struct _CONTEXT {
    DWORD ContextFlags;
    FLOATING_SAVE_AREA FloatSave;
    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;
    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;  
    DWORD   EFlags; 
    DWORD   Esp;
    DWORD   SegSs;
} CONTEXT;

typedef CONTEXT *PCONTEXT;


#define STATUS_WAIT_0                    ((DWORD   )0x00000000L)    
#define STATUS_ABANDONED_WAIT_0          ((DWORD   )0x00000080L)    
#define STATUS_USER_APC                  ((DWORD   )0x000000C0L)    
#define STATUS_TIMEOUT                   ((DWORD   )0x00000102L)    
//#define STATUS_PENDING                   ((DWORD   )0x00000103L)    
#define DBG_CONTINUE                     ((DWORD   )0x00010002L)    
#define DBG_TERMINATE_THREAD             ((DWORD   )0x40010003L)    
#define DBG_TERMINATE_PROCESS            ((DWORD   )0x40010004L)    
#define DBG_CONTROL_C                    ((DWORD   )0x40010005L)    
#define DBG_CONTROL_BREAK                ((DWORD   )0x40010008L)    
#define STATUS_GUARD_PAGE_VIOLATION      ((DWORD   )0x80000001L)    
#define STATUS_DATATYPE_MISALIGNMENT     ((DWORD   )0x80000002L)    
#define STATUS_BREAKPOINT                ((DWORD   )0x80000003L)    
#define STATUS_SINGLE_STEP               ((DWORD   )0x80000004L)    
#define DBG_EXCEPTION_NOT_HANDLED        ((DWORD   )0x80010001L)    
#define STATUS_ACCESS_VIOLATION          ((DWORD   )0xC0000005L)    
#define STATUS_IN_PAGE_ERROR             ((DWORD   )0xC0000006L)    
#define STATUS_INVALID_HANDLE            ((DWORD   )0xC0000008L)    
//#define STATUS_NO_MEMORY                 ((DWORD   )0xC0000017L)    
#define STATUS_ILLEGAL_INSTRUCTION       ((DWORD   )0xC000001DL)    
#define STATUS_NONCONTINUABLE_EXCEPTION  ((DWORD   )0xC0000025L)    
#define STATUS_INVALID_DISPOSITION       ((DWORD   )0xC0000026L)    
#define STATUS_ARRAY_BOUNDS_EXCEEDED     ((DWORD   )0xC000008CL)    
#define STATUS_FLOAT_DENORMAL_OPERAND    ((DWORD   )0xC000008DL)    
#define STATUS_FLOAT_DIVIDE_BY_ZERO      ((DWORD   )0xC000008EL)    
#define STATUS_FLOAT_INEXACT_RESULT      ((DWORD   )0xC000008FL)    
#define STATUS_FLOAT_INVALID_OPERATION   ((DWORD   )0xC0000090L)    
#define STATUS_FLOAT_OVERFLOW            ((DWORD   )0xC0000091L)    
#define STATUS_FLOAT_STACK_CHECK         ((DWORD   )0xC0000092L)    
#define STATUS_FLOAT_UNDERFLOW           ((DWORD   )0xC0000093L)    
#define STATUS_INTEGER_DIVIDE_BY_ZERO    ((DWORD   )0xC0000094L)    
#define STATUS_INTEGER_OVERFLOW          ((DWORD   )0xC0000095L)    
#define STATUS_PRIVILEGED_INSTRUCTION    ((DWORD   )0xC0000096L)    
#define STATUS_STACK_OVERFLOW            ((DWORD   )0xC00000FDL)    
#define STATUS_CONTROL_C_EXIT            ((DWORD   )0xC000013AL)    
#define STATUS_FLOAT_MULTIPLE_FAULTS     ((DWORD   )0xC00002B4L)    
#define STATUS_FLOAT_MULTIPLE_TRAPS      ((DWORD   )0xC00002B5L)    
#define STATUS_REG_NAT_CONSUMPTION       ((DWORD   )0xC00002C9L)    

#define BREAKPOINT_BREAK            0
#define BREAKPOINT_PRINT            1
#define BREAKPOINT_PROMPT           2
#define BREAKPOINT_LOAD_SYMBOLS     3
#define BREAKPOINT_UNLOAD_SYMBOLS   4
#define BREAKPOINT_RTLASSERT        5
#define BREAKPOINT_RIP              6
#define BREAKPOINT_LOAD_XESECTION   7
#define BREAKPOINT_UNLOAD_XESECTION 8
#define BREAKPOINT_CREATE_FIBER     9
#define BREAKPOINT_DELETE_FIBER     10
#define BREAKPOINT_KDPRINT          11

typedef PVOID PKEXCEPTION_FRAME;
typedef NTAPI BOOLEAN(*PKDEBUG_ROUTINE)(IN PKTRAP_FRAME TrapFrame, IN PKEXCEPTION_FRAME ExceptionFrame,IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord, IN BOOLEAN SecondChance);

ULONG(*MmQueryAddressProtectFix)(IN PVOID VirtualAddress);
KIRQL(*KeRaiseIrqlToDpcLevelFix)(void);
VOID(*KfLowerIrqlFix)(   KIRQL    NewIrql  );

/*
typedef struct _KDPC {
  CSHORT Type;
  BOOLEAN Inserted;
  UCHAR Padding;
  LIST_ENTRY DpcListEntry;
  PKDEFERRED_ROUTINE DeferredRoutine;
  PVOID DeferredContext;
  PVOID SystemArgument1;
  PVOID SystemArgument2;
} KDPC, *PKDPC, *RESTRICTED_POINTER PRKDPC;
*/


#define XC_FACTORY_START_INDEX 0x100
#define XC_FACTORY_AV_REGION (XC_FACTORY_START_INDEX+3)
#define XC_FACTORY_GAME_REGION (XC_FACTORY_START_INDEX+4)


#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2
