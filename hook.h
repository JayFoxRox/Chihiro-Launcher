// This file will be copied to the kernel space mostly.
// Moved code has some implications:
// - No stdlib or API
// - No arrays or strings
// - No globals
// - No static variables(?)
// - Don't move hookBase or hookEnvironment
// - Don't compile with optimizations
// - All local function pointers must manually be relocated. So if you want
// to make everything a lot easier and portable you should throw this away
// and add a proper relocator which keeps everything in memory. However, XBE
// size is cruical then so you'd want to compile with -Os and also discard
// unused sections / data (Both, strip and don't copy headers).
// The relocator should be copied from Cxbe. It has proven to work..

typedef struct {

	// Imports
  ANSI_STRING* XeImageFileName;
  PKTHREAD NTAPI(*KeGetCurrentThread)();
  ULONG NTAPI(*HalWriteSMBusValue)(UCHAR Address, UCHAR Command, BOOLEAN WordFlag, ULONG Value);
  VOID NTAPI(*RtlInitAnsiString)(IN OUT PANSI_STRING DestinationString,IN     PCSZ         SourceString);
  NTSTATUS NTAPI(*NtCreateFile)(OUT PHANDLE  FileHandle, IN  ACCESS_MASK  DesiredAccess,IN  POBJECT_ATTRIBUTES  ObjectAttributes,OUT PIO_STATUS_BLOCK  IoStatusBlock,IN  PLARGE_INTEGER  AllocationSize OPTIONAL, IN  ULONG  FileAttributes, IN  ULONG  ShareAccess, IN  ULONG  CreateDisposition, IN  ULONG  CreateOptions );
  NTSTATUS NTAPI(*NtWriteFile)(IN  HANDLE  FileHandle, IN  PVOID  Event,IN  PVOID  ApcRoutine,IN  PVOID  ApcContext,OUT  PVOID  IoStatusBlock,IN  PVOID  Buffer,IN  ULONG  Length,IN  PLARGE_INTEGER  ByteOffset);
  NTSTATUS NTAPI(*NtClose)(IN HANDLE Handle);
	NTSTATUS NTAPI(*NtQueryInformationFile)(   IN  HANDLE                      FileHandle,OUT PIO_STATUS_BLOCK            IoStatusBlock,OUT PVOID                       FileInformation, IN  ULONG                       Length, IN  FILE_INFORMATION_CLASS      FileInfo);
	NTSTATUS NTAPI(*NtSetInformationFile)(IN  HANDLE  FileHandle,OUT	PVOID	IoStatusBlock,IN	PVOID	FileInformation,IN	ULONG	Length,IN	ULONG	FileInformationClass);
	VOID NTAPI(*RtlEnterCriticalSection)(IN PRTL_CRITICAL_SECTION CriticalSection);
	BOOLEAN NTAPI(*RtlTryEnterCriticalSection)(IN PRTL_CRITICAL_SECTION CriticalSection);
	VOID NTAPI(*RtlLeaveCriticalSection)(IN PRTL_CRITICAL_SECTION CriticalSection);
	PVOID NTAPI(*MmAllocateContiguousMemory)(IN ULONG NumberOfBytes);
	VOID NTAPI(*MmFreeContiguousMemory)(IN PVOID BaseAddress);
	NTSTATUS NTAPI(*ExQueryNonVolatileSetting)(IN  DWORD               ValueIndex,	OUT DWORD              *Type,	OUT PUCHAR              Value,	IN  SIZE_T              ValueLength,	OUT PSIZE_T             ResultLength OPTIONAL);
  int(*RtlSprintf)(char *buffer, const char *format, ...);
  VOID NTAPI(*AvSendTVEncoderOption)(IN	PVOID	RegisterBase, IN	ULONG	Option, IN	ULONG	Param, OUT	ULONG	*Result);
  ULONG NTAPI(*AvSetDisplayMode)(IN PVOID	RegisterBase,IN ULONG	Step,IN ULONG	Mode,IN ULONG	Format,IN ULONG	Pitch,IN ULONG	FrameBuffer);
  ULONG NTAPI(*HalReadSMBusValue)(UCHAR   Address,UCHAR   Command,BOOLEAN WordFlag,PCHAR   Value);
  VOID NTAPI(*HalReadWritePCISpace)(IN ULONG   BusNumber,IN ULONG   SlotNumber,IN ULONG   RegisterNumber,IN PVOID   Buffer,IN ULONG   Length,IN BOOLEAN WritePCISpace);
  VOID NTAPI(*HalReturnToFirmware)(RETURN_FIRMWARE Routine);
  VOID NTAPI(*READ_PORT_BUFFER_UCHAR)(IN PUCHAR Port,IN PUCHAR Buffer,IN ULONG  Count);
  VOID NTAPI(*READ_PORT_BUFFER_USHORT)(IN PUSHORT Port,IN PUSHORT Buffer,IN ULONG   Count);
  VOID NTAPI(*READ_PORT_BUFFER_ULONG)(IN PULONG Port,IN PULONG Buffer,IN ULONG  Count);
  VOID NTAPI(*WRITE_PORT_BUFFER_UCHAR)(IN PUCHAR Port,IN PUCHAR Buffer,IN ULONG  Count);
  VOID NTAPI(*WRITE_PORT_BUFFER_USHORT)(IN PUSHORT Port,IN PUSHORT Buffer,IN ULONG   Count);
  VOID NTAPI(*WRITE_PORT_BUFFER_ULONG)(IN PULONG Port,IN PULONG Buffer,IN ULONG  Count);
  VOID NTAPI(*KeInitializeDpc)(KDPC                *Dpc,PKDEFERRED_ROUTINE   DeferredRoutine,PVOID                DeferredContext);
  KIRQL NTAPI(*KeGetCurrentIrql)(VOID);
  NTSTATUS NTAPI(*NtOpenFile)(OUT PHANDLE             FileHandle,IN  ACCESS_MASK         DesiredAccess,IN  POBJECT_ATTRIBUTES  ObjectAttributes,OUT PIO_STATUS_BLOCK    IoStatusBlock,IN  ULONG               ShareAccess,IN  ULONG               OpenOptions);
#define NTKERNELAPI NTAPI
  NTKERNELAPI BOOLEAN(*KeInsertQueueDpc)(IN /*PRKDPC*/PKDPC Dpc,IN PVOID SystemArgument1,IN PVOID SystemArgument2);
  DWORD* KeTickCount;
#define NTHALAPI NTKERNELAPI
#define FASTCALL __attribute__((fastcall))
  /*NTHALAPI*/ KIRQL (*FASTCALL KfRaiseIrql)(IN KIRQL NewIrql);
  /*NTHALAPI*/ VOID (*FASTCALL KfLowerIrql)(IN KIRQL NewIrql);
  NTSTATUS NTAPI(*NtSetIoCompletion)(IN HANDLE IoCompletionHandle,IN PVOID KeyContext,IN PVOID ApcContext,IN NTSTATUS IoStatus,IN ULONG_PTR IoStatusInformation);
  NTHALAPI KIRQL(*KeRaiseIrqlToDpcLevel)(void);
  NTSTATUS NTAPI(*KeDelayExecutionThread)(IN KPROCESSOR_MODE  WaitMode,IN BOOLEAN          Alertable,IN PLARGE_INTEGER   Interval);
	// Data
  struct {
    Tss_t tss;
    uint8_t iomap[0x4100/8];  
  };
  char crash[80];
  struct {
    char stringEip[10];
    char stringEax[10];
    char stringEcx[10];
    char stringEdx[10];
    char stringEsp[10];
    char stringEbp[10];
    char stringEsi[10];
    char stringEdi[10];
    char stringCode[10];
    char stringStack[10];
    char stringExceptionFlags[30];
    char stringExceptionCode[30];
    char stringExceptionRecord[30];
    char stringXbe[10];
    char stringPrint[10];
    char stringTimestamp[30];
    char stringIn[10];
    char stringOut[10];
    char stringKeDelayExecutionThreadArguments[100];
    char stringKeRaiseIrqlToDpcLevelArguments[100];
    char stringKfLowerIrqlArguments[100];
    char stringKfRaiseIrqlArguments[100];
    char stringRtlLeaveCriticalSectionArguments[100];
    char stringRtlEnterCriticalSectionArguments[100];
    char stringRtlTryEnterCriticalSectionArguments[100];
    char stringExQueryNonVolatileSettingArguments[100];
    char stringAvSendTVEncoderOptionArguments[100];
    char stringAvSetDisplayModeArguments[100];
    char stringReadPortArguments[100];
    char stringWritePortArguments[100];
    char stringHalReadSMBusValueArguments[100];
    char stringHalWriteSMBusValueArguments[100];
    char stringHalReadWritePCISpaceArguments[100];
    char stringHalReturnToFirmwareArguments[100];
    char stringKeInitializeDpcArguments[100];
    char stringNtCreateFileArguments[200];
    char stringNtOpenFileArguments[200];
    char stringNtSetIoCompletionArguments[200];
  };
  
  uint8_t code[8*500]; // A maximum of 500 kernel hooks.. should be enough

} HookEnvironment_t;

#include <stdint.h>

#define STRING(var,text) \
const char* var; \
__asm__ __volatile__("call next\n" \
                     "dat: .asciz \"" text "\"\n" \
                     "next:\n" \
                     "pop %%eax" \
                     :"=a"(var));

HookEnvironment_t* hook(void* base); //FIXME: Rename to hookDetour or something?

void hookEnvironment(void);
#define he ((HookEnvironment_t*)(hookBase()+(uintptr_t)hookEnvironment-(uintptr_t)hookBase))

uintptr_t volatile hookBase(void) {
  //FIXME: Somehow put this into a getEip() macro?
  __asm__ __volatile__("call eip\n"
                       "eip:\n"
                       "pop %%eax\n"
                       "sub $8,%%eax\n" /* 3 bytes for gcc stuff, 5 for the call */
                       "leave\n"
                       "ret":);
}


void installIoDebugger(void) {

	// Seen: 401E,4020,4022,4024,4026,4080,4084,408E,40F0
	// 401F  XXXXXXXXXXXXXX
	// 4025 							  XXXXXXXXX
	// 4081														XXXXXXXXX
	// 408F																			XXXX
	// 40F1																					 XXXX

	asm(
			//"mov $0x4000,%%eax\nmov %%eax,%%dr0\n"
      //"mov $0x4002,%%eax\nmov %%eax,%%dr3\n"
      //"mov $0x4006,%%eax\nmov %%eax,%%dr1\n"      
      //"mov $0x401E,%%eax\nmov %%eax,%%dr0\n"
      //"mov $0x4020,%%eax\nmov %%eax,%%dr0\n"
			//"mov $0x4022,%%eax\nmov %%eax,%%dr1\n"
			//"mov $0x4024,%%eax\nmov %%eax,%%dr2\n"
			//"mov $0x4026,%%eax\nmov %%eax,%%dr2\n"	
      //"mov $0x4080,%%eax\nmov %%eax,%%dr0\n"		
			//"mov $0x4084,%%eax\nmov %%eax,%%dr2\n"
			//"mov $0x4088,%%eax\nmov %%eax,%%dr2\n"
			//"mov $0x408E,%%eax\nmov %%eax,%%dr1\n"
			//"mov $0x4090,%%eax\nmov %%eax,%%dr1\n"
			//"mov $0x40F0,%%eax\nmov %%eax,%%dr3\n"
			//"mov $0x40F4,%%eax\nmov %%eax,%%dr3\n"

      "mov $0x401E,%%eax\nmov %%eax,%%dr0\n" // Expected to be read at startup
			"mov $0x4090,%%eax\nmov %%eax,%%dr1\n" // Reset
			"mov $0x40F0,%%eax\nmov %%eax,%%dr2\n" // Query DIMM Size or revision
      "mov $0x40F4,%%eax\nmov %%eax,%%dr3\n" // Same
			"mov %%dr7,%%eax\n"
			"andl $0x0000FC00,%%eax\n"
			"orl $0xEEEE03FF,%%eax\n"
			"mov %%eax,%%dr7\n"
			"mov %%cr4,%%eax\n"
			"orl $0x00000008,%%eax\n"
			"mov %%eax,%%cr4"
			:
			:
			:"eax");

  return;

}


// Positive length = Print bytes normally
// Negative length = Print bytes in reverse order
char* hexString(char* s, uint8_t* data, signed int length) { 
  int i;
  for(i = 0; i < ((length>0)?length:-length)*2; i++) {
    uint8_t value = data[(length>0)?(i/2):(~length-(i/2))];
    uint8_t digit = (value >> (((i+1)%2)*4)) & 0xF;
    if (digit <= 0x9) {
      s[i] = '0' + (digit-0);
    } else {
      s[i] = 'A' + (digit-0xA);
    }
  }
  s[i] = '\0';
  return &s[i];
}

char* symbol(char* s, char symbol) {
  *s++ = symbol;
  *s = '\0';
  return s;
}

char* copyLimitedString(char* s1, const char* s2, size_t size) {
  while(*s2 && size) { *s1++ = *s2++; size--; }
  *s1 = '\0';
  return s1;
}

char* copyString(char* s1, const char* s2) {
  while(*s2) { *s1++ = *s2++; }
  *s1 = '\0';
  return s1;
}

typedef struct {
  KDPC kdpc;
  char* file;
  char* text;
} AppendFileDpc_t;

void appendFile(const char* file, const char* text);

VOID __stdcall appendFileDpc(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	KIRQL irql = he->KeGetCurrentIrql();
	
  AppendFileDpc_t* dpcMemory = DeferredContext;
  if (irql == 0) { // Still not there yet..
	  appendFile(dpcMemory->file,dpcMemory->text);
	} else {
//		leds(0xF4);
	}
  he->MmFreeContiguousMemory(dpcMemory->text);
  he->MmFreeContiguousMemory(dpcMemory->file);

//	he->MmFreeContiguousMemory(dpcMemory);   //FIXME: Can I free the KDPC object memory here?!

  return;
}

size_t stringLength(char* s) {
	size_t l = 0;
  while(*s++) { l++; }
	return l;
}

void forceAppendFile(const char* file, const char* text) {

  unsigned int len = stringLength(text);

#if 0 // FIXME: Find a way to get below DPC
  KIRQL irql = he->KeGetCurrentIrql();
  if (irql > PASSIVE_LEVEL) {
LEDS(0x1E);
return;
    unsigned int flen = stringLength(file);

    AppendFileDpc_t* dpcMemory = he->MmAllocateContiguousMemory(sizeof(AppendFileDpc_t));

    dpcMemory->text = he->MmAllocateContiguousMemory(len+1);
    copyString(dpcMemory->text,text);

    dpcMemory->file = he->MmAllocateContiguousMemory(flen+1);
    copyString(dpcMemory->file,file);

    he->KeInitializeDpc(&dpcMemory->kdpc,hookBase()+(uintptr_t)appendFileDpc-(uintptr_t)hookBase,dpcMemory);
    he->KeInsertQueueDpc(&dpcMemory->kdpc,NULL,NULL);

    return;
  }
#endif

	ANSI_STRING string;
	IO_STATUS_BLOCK ioStatusBlock;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };

	he->RtlInitAnsiString(&string,file);
	
	// Kernel object attributes (ignore case, use system root) 
	objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
	objectAttributes.ObjectName = &string;
	objectAttributes.RootDirectory = NULL;

	HANDLE fh;
	NTSTATUS ret = he->NtCreateFile(&fh,GENERIC_WRITE | SYNCHRONIZE,&objectAttributes,&ioStatusBlock,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ | FILE_SHARE_WRITE,FILE_OPEN_IF , FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH);	


// Seek to end of file
	FILE_NETWORK_OPEN_INFORMATION openInfo;

	ret = he->NtQueryInformationFile(fh, &ioStatusBlock,&openInfo, sizeof(openInfo), FileNetworkOpenInformation);

	FILE_POSITION_INFORMATION positionInfo;
	LARGE_INTEGER             targetPointer;

	positionInfo.CurrentByteOffset.u.HighPart = openInfo.EndOfFile.u.HighPart;
	positionInfo.CurrentByteOffset.u.LowPart= openInfo.EndOfFile.u.LowPart;

	ret = he->NtSetInformationFile(fh, &ioStatusBlock, &positionInfo, sizeof(positionInfo), FilePositionInformation);


//printf("1: %X\n",ret);

//printf("Writing %i bytes!\n",len);



	ret = he->NtWriteFile(fh,NULL,NULL,NULL,&ioStatusBlock,text,len,NULL);
//printf("2: %X\n",ret);

	ret = he->NtClose(fh);
//printf("3: %X\n",ret);

  LEDS(0x00);

  return;

}

void appendFile(const char* file, const char* text) {
  KIRQL irql = he->KeGetCurrentIrql();
  if (irql > PASSIVE_LEVEL) {
    LEDS(0x1E);
    return;
  }
  forceAppendFile(file,text);
  return;
}

void leds(uint8_t pwm) {
#if 0
  if (he->KeGetCurrentIrql() < DISPATCH_LEVEL) {
    he->HalWriteSMBusValue(0x20, 0x08, FALSE, pwm); // Red PWM | Green PWM
    he->HalWriteSMBusValue(0x20, 0x07, FALSE, 0x01); // Overwrite
  } else {
    LEDS(pwm);
  }
#else
  // I was worried that the SMBus writes will sit in some buffer so I do this
  LEDS(pwm);
#endif
  return;
}

#define decString hexString


char* stackDump(char* p, void* base, unsigned int depth) {
  uint32_t* stack = base;
  uint8_t index;
  for(index = 1; index <= depth; index++) {
	  p = symbol(p,'\t');	p = symbol(p,'\t');
	  p = symbol(p,'['); p = decString(p,&index,-1);	p = symbol(p,']');
	  p = symbol(p,' ');
	  p = symbol(p,'0'); p = symbol(p,'x'); p = hexString(p,&stack[index-1],-4);
	  p = symbol(p,'\n');
  }
  return p;
}


char* stackTrace(char* p, PCONTEXT ContextRecord, unsigned int maximumDepth, unsigned int contentDepth) {

  uint8_t level;
//  debugPrintf("Xbox Stacktrace:\n\n");
//  debugPrintf("\tAt: '%s' (%s:%u)\n",sym,fil,lin);

  uintptr_t base = ContextRecord->Ebp;
  for(level = 1; level <= maximumDepth; level++) {

    if ((base < 0xD0000000) || (base >= 0xE0000000)) {
			p = symbol(p,'\t');	p = symbol(p,'\t');
			p = symbol(p,'B'); p = symbol(p,'B');	p = symbol(p,'a'); p = symbol(p,'s');	p = symbol(p,'e');
			p = symbol(p,' ');
			p = symbol(p,'0'); p = symbol(p,'x'); p = hexString(p,&base,-4);
			p = symbol(p,'\n');
      break;
    }

    uint32_t* stack = base;
    base = stack[0];
    uintptr_t returnTo = stack[1];
    stackDump(p,&stack[2],contentDepth);
    if (contentDepth > 0) {
			p = symbol(p,'\t');	p = symbol(p,'\t');
			p = symbol(p,'.'); p = symbol(p,'.'); p = symbol(p,'.');
			p = symbol(p,'\n'); p = symbol(p,'\n');
    }
		p = symbol(p,'\t');
		p = decString(p,&level,-1);	p = symbol(p,'.'); p = symbol(p,' '); 
		p = symbol(p,'F'); p = symbol(p,'r');	p = symbol(p,'o'); p = symbol(p,'m'); p = symbol(p,':'); p = symbol(p,' ');
		p = symbol(p,'0'); p = symbol(p,'x'); p = hexString(p,&returnTo,-4);
		p = symbol(p,'\n');

    if ((returnTo == 0xDEADC0DE) || (returnTo == 0)) { //FIXME: Should be looking for zero instead, but thread.c is using 0xDEADC0DE atm because it's easier to spot
      //debugPrintf("(Probably end of thread, stopping)\n");
			p = symbol(p,'B'); p = symbol(p,'R');	p = symbol(p,'e'); p = symbol(p,'t');	p = symbol(p,'n');
			p = symbol(p,'\n');
      break;
    } 
  }  
  if (level == maximumDepth) {
		p = symbol(p,'\t');
		p = symbol(p,'.'); p = symbol(p,'.'); p = symbol(p,'.');
		p = symbol(p,'\n'); p = symbol(p,'\n');
	}
	p = symbol(p,'\n');
	return p;
}

char* timestamp(char* s) {
  return &s[he->RtlSprintf(s,he->stringTimestamp,*he->KeTickCount,he->KeGetCurrentIrql(),he->KeGetCurrentThread())];
}


NTAPI BOOLEAN hookKiDebugRoutine(IN PKTRAP_FRAME TrapFrame, IN PKEXCEPTION_FRAME ExceptionFrame,IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord, IN BOOLEAN SecondChance) {

//LEDS(0x44);

//he->RtlEnterCriticalSection(&he->critSect);
installIoDebugger();


  if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
    char x[100];
    char* p = timestamp(x);
    uint8_t* code = ContextRecord->Eip;
    if (code[-1] == 0xED) {
      p = copyString(p,he->stringIn);
      if (code[-2] == 0x66) {
        // in %dx,%ax
        p = symbol(p,'w'); p = symbol(p,'=');
        p = hexString(p,&ContextRecord->Edx,-2);
      } else {
        // in %dx,%eax
        p = symbol(p,'l'); p = symbol(p,'=');
        p = hexString(p,&ContextRecord->Edx,-2);
      }
    } else if (code[-1] == 0xEC) {
      // in %dx,%al
      p = copyString(p,he->stringIn);
      p = symbol(p,'b'); p = symbol(p,'=');
      p = hexString(p,&ContextRecord->Edx,-2);
    } else if (code[-1] == 0xEE) {
      // out    %al,(%dx)      
      p = copyString(p,he->stringOut);
      p = hexString(p,&ContextRecord->Edx,-2); p = symbol(p,'=');
      p = hexString(p,&ContextRecord->Eax,-1);
    } else if (code[-1] == 0xEF) { 
      p = copyString(p,he->stringOut);
      if (code[-2] == 0x66) {
        // out    %ax,(%dx)
        p = hexString(p,&ContextRecord->Edx,-2); p = symbol(p,'=');
        p = hexString(p,&ContextRecord->Eax,-2);
      } else {
        // out    %eax,(%dx)
        p = hexString(p,&ContextRecord->Edx,-2); p = symbol(p,'=');
        p = hexString(p,&ContextRecord->Eax,-4);
      }
    } else {
      LEDS(0xE0)
      p = symbol(p,'\n');
      appendFile(he->crash,x);
      return FALSE;
    }            	
    LEDS(0x0E)
    p = symbol(p,'\n');
    appendFile(he->crash,x);
    return TRUE;    
  }


  if (he->KeGetCurrentIrql > DISPATCH_LEVEL) {
    leds(0xE1);
  } else {
    char* x = he->MmAllocateContiguousMemory(0x1000);
    char* p;

    p = x; *p = '\0';


    p = symbol(p,'\n');
    p = symbol(p,'\n');
    p = timestamp(p);
    p = symbol(p,'\n');
    p = copyString(p,he->stringXbe); p = copyLimitedString(p,he->XeImageFileName->Buffer,he->XeImageFileName->Length); p = symbol(p,'\n');
    p = symbol(p,'\n');
    p = copyString(p,he->stringExceptionCode); p = hexString(p,&ExceptionRecord->ExceptionCode,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringExceptionFlags); p = hexString(p,&ExceptionRecord->ExceptionFlags,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringExceptionRecord); p = hexString(p,&ExceptionRecord->ExceptionRecord,-4); p = symbol(p,'\n');
    p = symbol(p,'\n');
    p = copyString(p,he->stringEip); p = hexString(p,&ContextRecord->SegCs,-2); p = symbol(p,':'); p = hexString(p,&ContextRecord->Eip,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringEsi); p = hexString(p,&ContextRecord->Esi,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringEdi); p = hexString(p,&ContextRecord->Edi,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringEbp); p = hexString(p,&ContextRecord->Ebp,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringEsp); p = hexString(p,&ContextRecord->SegSs,-2); p = symbol(p,':'); p = hexString(p,&ContextRecord->Esp,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringEax); p = hexString(p,&ContextRecord->Eax,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringEcx); p = hexString(p,&ContextRecord->Ecx,-4); p = symbol(p,'\n');
    p = copyString(p,he->stringEdx); p = hexString(p,&ContextRecord->Edx,-4); p = symbol(p,'\n');
    p = symbol(p,'\n');
    p = copyString(p,he->stringCode); p = hexString(p,ContextRecord->Eip-10,10); p = symbol(p,' '); p = hexString(p,ContextRecord->Eip,1); p = symbol(p,' '); p = hexString(p,ContextRecord->Eip+1,10); p = symbol(p,'\n');
    p = copyString(p,he->stringStack); p = hexString(p,ContextRecord->Esp-10,10); p = symbol(p,' '); p = hexString(p,ContextRecord->Esp,1); p = symbol(p,' '); p = hexString(p,ContextRecord->Esp+1,10); p = symbol(p,'\n');

    appendFile(he->crash,x); p = x; *p = '\0';

    p = symbol(p,'\n');
    p = stackTrace(p,ContextRecord,10,10);
    p = symbol(p,'\n');

    appendFile(he->crash,x); p = x; *p = '\0';

    for(int i = 0; i < 10; i++){
	    p = symbol(p,'-');	
    }
    p = symbol(p,'\n');

    appendFile(he->crash,x);

    he->MmFreeContiguousMemory(x);
  }


/*
  if (ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
	  if (ContextRecord->Eax == BREAKPOINT_PRINT) {
      leds(0xFF);
      char x[100];
      char* p = x;
		  struct {
			  uint16_t  length;
			  uint16_t  maximumLength;
			  uint32_t  bufferAddress;
		  }* tmp = ContextRecord->Ecx;
		  p = copyString(p,he->stringPrint); p = symbol(p,'\'');
      int l = tmp->length;
      if (l > 70) { l = 70; }
		  if (tmp->bufferAddress) { p = copyLimitedString(p,tmp->bufferAddress,l); }
		  p = symbol(p,'\''); p = symbol(p,'\n');
      appendFile(he->crash,x);
	  }
  }
*/


//he->RtlLeaveCriticalSection(&he->critSect);

  //NOTE: This block is also what the xbox kernel would do without debugger!
  if (ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
    if (ExceptionRecord->NumberParameters > 0) {
      if ((ExceptionRecord->ExceptionInformation[0] == BREAKPOINT_LOAD_SYMBOLS)||(ExceptionRecord->ExceptionInformation[0] == BREAKPOINT_UNLOAD_SYMBOLS) ||
      (ExceptionRecord->ExceptionInformation[0] == BREAKPOINT_LOAD_XESECTION)||(ExceptionRecord->ExceptionInformation[0] == BREAKPOINT_UNLOAD_XESECTION) ||
      (ExceptionRecord->ExceptionInformation[0] == BREAKPOINT_PRINT) ||
      (ExceptionRecord->ExceptionInformation[0] == BREAKPOINT_KDPRINT)) {
      	leds(0xF0);

        ContextRecord->Eip++;
        return TRUE;
      }
    }
  }

  if (ExceptionRecord->ExceptionCode == 0x80000003) {
    if (ContextRecord) {
      uint8_t* code =  ContextRecord->Eip;
      if (*code == 0xCC) {

        if ((code >= (he->code)) && (code < ((he->code)+500*8))) {
          char x[500];
          char* p;
          p = timestamp(x);
          uint32_t offset = (uintptr_t)ContextRecord->Eip - (uintptr_t)(he->code);
          offset /= 8;
          offset += 1; // Add the ordinalBase..
          offset |= 0xC0DE0000;
          if ((((uintptr_t)ContextRecord->Eip - (uintptr_t)(he->code)) % 8) < 4) {

            p = symbol(p,'C'); p = symbol(p,':'); p = symbol(p,' ');
            p = hexString(p,&offset,-4);
            p = symbol(p,'\n');

            p = stackDump(p,ContextRecord->Esp,10);
            p = symbol(p,'\n');

            // Could rewrite stack here to ContextRecord->Eip + 5 (?)
            // Then we would get a int3 on return
            // The return address would have to be stored elsewhere and restored below

          } else {

            p = symbol(p,'R'); p = symbol(p,':'); p = symbol(p,' ');
            p = hexString(p,&offset,-4);
            p = symbol(p,'\n');

          } 
          appendFile(he->crash,x);
        }

        ContextRecord->Eip++;

        return TRUE;
      }
    }
  }
  leds(0xA6);

  if (SecondChance == FALSE) {
    return FALSE;
  }

  return FALSE;
//  while(1);
}

NTSTATUS NTAPI hookExQueryNonVolatileSetting(IN  DWORD               ValueIndex,	OUT DWORD              *Type,	OUT PUCHAR              Value,	IN  SIZE_T              ValueLength,	OUT PSIZE_T             ResultLength OPTIONAL) {

  //FIXME: Find another way to unload it all
  if ((Value == 0x13371337) && (Type == 0x13371337)) {
	  hook(NULL);
	  return 0x13371337;
  }

  // This function usually gets called first, so until I have some other "Startup" hook this will have to do..
  installIoDebugger();

	char x[600];
	char* p = timestamp(x);	
  p = &p[he->RtlSprintf(p,he->stringExQueryNonVolatileSettingArguments,ValueIndex,Type,Value,ValueLength,ResultLength)];
	NTSTATUS ret = he->ExQueryNonVolatileSetting(ValueIndex,Type,Value,ValueLength,ResultLength);
	p = hexString(p,&ret,-4); p = symbol(p,',');
	appendFile(he->crash,x);
  p = x; *p = '\0';
	p = symbol(p,'D'); p = symbol(p,':'); p = hexString(p,Value,ResultLength?*ResultLength:ValueLength);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

VOID NTAPI hookKeInitializeDpc(KDPC *Dpc,   PKDEFERRED_ROUTINE   DeferredRoutine, PVOID                DeferredContext) {
	char x[100];
  char* p = timestamp(x);	
  p = &p[he->RtlSprintf(p,he->stringKeInitializeDpcArguments,Dpc,DeferredRoutine,DeferredContext)];
  he->KeInitializeDpc(Dpc,DeferredRoutine,DeferredContext);
	p = symbol(p,'\n');

  KIRQL irql = he->KeGetCurrentIrql();
  if (irql == PASSIVE_LEVEL) {
	  appendFile(he->crash,x);  
	}

	return;
}

VOID NTAPI hookAvSendTVEncoderOption(IN	PVOID	RegisterBase, IN	ULONG	Option, IN	ULONG	Param, OUT	ULONG	*Result) {
	char x[200];
  char* p = timestamp(x);	
  p = &p[he->RtlSprintf(p,he->stringAvSendTVEncoderOptionArguments,RegisterBase,Option,Param,Result)];
	he->AvSendTVEncoderOption(RegisterBase,Option,Param,Result);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return;
}

ULONG NTAPI hookAvSetDisplayMode(IN PVOID	RegisterBase,IN ULONG	Step,IN ULONG	Mode,IN ULONG	Format,IN ULONG	Pitch,IN ULONG	FrameBuffer) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringAvSetDisplayModeArguments,RegisterBase,Step,Mode,Format,Pitch,FrameBuffer)];
  ULONG ret = he->AvSetDisplayMode(RegisterBase,Step,Mode,Format,Pitch,FrameBuffer);
	p = hexString(p,&ret,-4);	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

NTSTATUS NTAPI hookNtSetIoCompletion(IN HANDLE IoCompletionHandle,IN PVOID KeyContext,IN PVOID ApcContext,IN NTSTATUS IoStatus,IN ULONG_PTR IoStatusInformation) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringNtSetIoCompletionArguments,IoCompletionHandle,KeyContext,ApcContext,IoStatus,IoStatusInformation)];
  NTSTATUS ret = he->NtSetIoCompletion(IoCompletionHandle,KeyContext,ApcContext,IoStatus,IoStatusInformation);
	p = hexString(p,&ret,-4);	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

ULONG NTAPI hookHalReadSMBusValue(UCHAR   Address,UCHAR   Command,BOOLEAN WordFlag,PCHAR   Value) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringHalReadSMBusValueArguments,Address,Command,WordFlag,Value)];
  ULONG ret = he->HalReadSMBusValue(Address,Command,WordFlag,Value);
	p = hexString(p,&ret,-4);	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return ret;
}
ULONG NTAPI hookHalWriteSMBusValue(UCHAR Address, UCHAR Command, BOOLEAN WordFlag, ULONG Value) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringHalWriteSMBusValueArguments,Address,Command,WordFlag,Value)];
  ULONG ret = he->HalWriteSMBusValue(Address,Command,WordFlag,Value);
	p = hexString(p,&ret,-4);	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return ret;
}
VOID NTAPI hookHalReadWritePCISpace(IN ULONG   BusNumber,IN ULONG   SlotNumber,IN ULONG   RegisterNumber,IN PVOID   Buffer,IN ULONG   Length,IN BOOLEAN WritePCISpace) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringHalReadWritePCISpaceArguments,BusNumber,SlotNumber,RegisterNumber,Buffer,Length,WritePCISpace)];
  he->HalReadWritePCISpace(BusNumber,SlotNumber,RegisterNumber,Buffer,Length,WritePCISpace);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return;
}
VOID NTAPI hookHalReturnToFirmware(RETURN_FIRMWARE Routine) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringHalReturnToFirmwareArguments,Routine)];
	p = symbol(p,'\n');
 	appendFile(he->crash,x);
  he->HalReturnToFirmware(Routine);
}
VOID NTAPI hookREAD_PORT_BUFFER_UCHAR(IN PUCHAR Port,IN PUCHAR Buffer,IN ULONG  Count) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringReadPortArguments,'B',Port,Buffer,Count)];
  he->READ_PORT_BUFFER_UCHAR(Port,Buffer,Count);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return;
}
VOID NTAPI hookREAD_PORT_BUFFER_USHORT(IN PUSHORT Port,IN PUSHORT Buffer,IN ULONG   Count) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringReadPortArguments,'W',Port,Buffer,Count)];
  he->READ_PORT_BUFFER_USHORT(Port,Buffer,Count);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return;
}
VOID NTAPI hookREAD_PORT_BUFFER_ULONG(IN PULONG Port,IN PULONG Buffer,IN ULONG  Count) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringReadPortArguments,'L',Port,Buffer,Count)];
  he->READ_PORT_BUFFER_ULONG(Port,Buffer,Count);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return;
}
VOID NTAPI hookWRITE_PORT_BUFFER_UCHAR(IN PUCHAR Port,IN PUCHAR Buffer,IN ULONG  Count) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringWritePortArguments,'B',Port,Buffer,Count)];
  he->WRITE_PORT_BUFFER_UCHAR(Port,Buffer,Count);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return;
}
VOID NTAPI hookWRITE_PORT_BUFFER_USHORT(IN PUSHORT Port,IN PUSHORT Buffer,IN ULONG   Count) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringWritePortArguments,'W',Port,Buffer,Count)];
  he->WRITE_PORT_BUFFER_USHORT(Port,Buffer,Count);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return;
}
VOID NTAPI hookWRITE_PORT_BUFFER_ULONG(IN PULONG Port,IN PULONG Buffer,IN ULONG  Count) {
	char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringWritePortArguments,'L',Port,Buffer,Count)];
  he->WRITE_PORT_BUFFER_ULONG(Port,Buffer,Count);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
  return;
}

NTSTATUS NTAPI hookNtCreateFile(OUT PHANDLE             FileHandle, IN  ACCESS_MASK         DesiredAccess,IN  POBJECT_ATTRIBUTES	ObjectAttributes,OUT PIO_STATUS_BLOCK	IoStatusBlock,IN  PLARGE_INTEGER	    AllocationSize OPTIONAL, IN  ULONG	            FileAttributes, IN  ULONG	            ShareAccess, IN  ULONG	            CreateDisposition, IN  ULONG	            CreateOptions) {
	char x[500];
	char* p = timestamp(x);
  ANSI_STRING* n = ObjectAttributes->ObjectName;
  p = &p[he->RtlSprintf(p,he->stringNtCreateFileArguments,FileHandle, DesiredAccess, ObjectAttributes, n->Length, n->Buffer, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions)];
	NTSTATUS ret = he->NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions);
	p = hexString(p,&ret,-4);	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

NTSTATUS NTAPI hookNtOpenFile(OUT PHANDLE             FileHandle,IN  ACCESS_MASK         DesiredAccess,IN  POBJECT_ATTRIBUTES  ObjectAttributes,OUT PIO_STATUS_BLOCK    IoStatusBlock,IN  ULONG               ShareAccess,IN  ULONG               OpenOptions) {
  char x[500];
	char* p = timestamp(x);
  ANSI_STRING* n = ObjectAttributes->ObjectName;
  p = &p[he->RtlSprintf(p,he->stringNtOpenFileArguments,FileHandle, DesiredAccess, ObjectAttributes, n->Length, n->Buffer,IoStatusBlock, ShareAccess, OpenOptions)];
  NTSTATUS ret = he->NtOpenFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock, ShareAccess, OpenOptions);
	p = hexString(p,&ret,-4);	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

BOOLEAN NTAPI hookRtlTryEnterCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
  char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringRtlTryEnterCriticalSectionArguments,CriticalSection)];
  BOOLEAN ret = he->RtlTryEnterCriticalSection(CriticalSection);
	p = symbol(p,(ret==TRUE)?'1':'0');
	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

VOID NTAPI hookRtlEnterCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
  char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringRtlEnterCriticalSectionArguments,CriticalSection)];
  he->RtlEnterCriticalSection(CriticalSection);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return;
}

VOID NTAPI hookRtlLeaveCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
  char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringRtlLeaveCriticalSectionArguments,CriticalSection)];
  he->RtlLeaveCriticalSection(CriticalSection);
	p = symbol(p,'\n');
	appendFile(he->crash,x);
	return;
}

/*NTHALAPI*/ KIRQL FASTCALL hookKfRaiseIrql(IN KIRQL NewIrql){
  char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringKfRaiseIrqlArguments,NewIrql)];
  KIRQL ret = he->KfRaiseIrql(NewIrql);
	p = hexString(p,&ret,-sizeof(ret)); p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

/*NTHALAPI*/ VOID FASTCALL hookKfLowerIrql(IN KIRQL NewIrql) {
  char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringKfLowerIrqlArguments,NewIrql)];
  he->KfLowerIrql(NewIrql);
  p = symbol(p,'\n');
	appendFile(he->crash,x);
	return;
}

NTHALAPI KIRQL hookKeRaiseIrqlToDpcLevel(void) {
  char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringKeRaiseIrqlToDpcLevelArguments)];
  KIRQL ret = he->KeRaiseIrqlToDpcLevel();
	p = hexString(p,&ret,-sizeof(ret)); p = symbol(p,'\n');
	appendFile(he->crash,x);
	return ret;
}

NTSTATUS NTAPI hookKeDelayExecutionThread(IN KPROCESSOR_MODE  WaitMode,IN BOOLEAN          Alertable,IN PLARGE_INTEGER   Interval) {
  char x[200];
	char* p = timestamp(x);
  p = &p[he->RtlSprintf(p,he->stringKeDelayExecutionThreadArguments,WaitMode,Alertable,Interval)];
  NTSTATUS ret = he->KeDelayExecutionThread(WaitMode,Alertable,Interval);
	p = hexString(p,&ret,-4); p = symbol(p,'\n');
	appendFile(he->crash,x);
  return ret;
}

HookEnvironment_t* hook(void* base) {

  HookEnvironment_t* environment;

	uintptr_t kernel = 0x80010000;
	uintptr_t kernelHeader = kernel + *(uint32_t*)(kernel+0x3C);	
	uintptr_t exportDirectoryTable = kernel + *(uint32_t*)(kernelHeader+0x78); //FIXME: This is pretty dirty?! going accross table borders etc - ignoring size?!
	uint32_t* exportAddressTableRva = kernel + *(uint32_t*)(exportDirectoryTable+0x1C);
	uint32_t ordinalBase = *(uint32_t*)(exportDirectoryTable+0x10);
	exportAddressTableRva = &exportAddressTableRva[-ordinalBase]; // Base offet

	// Initiate an unload first
	if (base!=NULL) {
    NTSTATUS NTAPI(*reloadedExQueryNonVolatileSetting)(IN  DWORD               ValueIndex,	OUT DWORD              *Type,	OUT PUCHAR              Value,	IN  SIZE_T              ValueLength,	OUT PSIZE_T             ResultLength OPTIONAL);
    reloadedExQueryNonVolatileSetting = kernel + exportAddressTableRva[24];
		reloadedExQueryNonVolatileSetting(0,0x13371337,0x13371337,0,NULL);
    //FIXME: If this returned 0x13371337 we know that we just unloaded our hook!

    // Fill the new environment
    size_t hookFunctionSize = (uintptr_t)hookEnvironment - (uintptr_t)hookBase;
    size_t hookEnvironmentSize = sizeof(HookEnvironment_t);
    size_t hookSize = hookFunctionSize + hookEnvironmentSize;

    environment = (void*)((uintptr_t)base + hookFunctionSize);

    // Kernel variables
    environment->XeImageFileName = &XeImageFileName;
    environment->KeTickCount = &KeTickCount;
	  // Functions
    environment->RtlInitAnsiString = RtlInitAnsiString;
    environment->NtWriteFile = NtWriteFile;
    environment->NtClose = NtClose;
	  environment->NtQueryInformationFile = NtQueryInformationFile;
	  environment->NtSetInformationFile = NtSetInformationFile;
	  environment->MmAllocateContiguousMemory = MmAllocateContiguousMemory;
	  environment->MmFreeContiguousMemory = MmFreeContiguousMemory;
    environment->KeGetCurrentThread = KeGetCurrentThread;
    // (Imported by ordinal because OpenXDK sucks)
    #define IMPORT(o,x) {	environment->x = kernel+exportAddressTableRva[o]; }
    IMPORT(362,RtlSprintf);
    IMPORT(103,KeGetCurrentIrql);
    IMPORT(119,KeInsertQueueDpc);
	  // Hooked functions
	  // 	 These must be imported by ordinal because if this launcher is started
	  // 	 with an already hooked kernel (mostly during development after recompile)
	  // 	 it would hook the already hooked functions.
	  // 	 To avoid this I use hook(NULL) to turn it back to normal.
	  // 	 However, this will restore the export table - but this launcher still uses
	  // 	 the old (hooked) export table, so we have to "reimport" manually
    IMPORT(0xDB,NtReadFile)
    IMPORT(0x121,RtlInitAnsiString)
    IMPORT(0x63,KeDelayExecutionThread)
    IMPORT(50,HalWriteSMBusValue)
    IMPORT(45,HalReadSMBusValue)
    IMPORT(46,HalReadWritePCISpace)
    IMPORT(49,HalReturnToFirmware)
    IMPORT(329,READ_PORT_BUFFER_UCHAR)
    IMPORT(330,READ_PORT_BUFFER_USHORT)
    IMPORT(331,READ_PORT_BUFFER_ULONG)
    IMPORT(332,WRITE_PORT_BUFFER_UCHAR)
    IMPORT(333,WRITE_PORT_BUFFER_USHORT)
    IMPORT(334,WRITE_PORT_BUFFER_ULONG)
    IMPORT(2,AvSendTVEncoderOption)
    IMPORT(3,AvSetDisplayMode)
    IMPORT(107,KeInitializeDpc)
	  IMPORT(190,NtCreateFile)
    IMPORT(202,NtOpenFile)
    IMPORT(227,NtSetIoCompletion)
    IMPORT(0x126,RtlLeaveCriticalSection)
    IMPORT(0x115,RtlEnterCriticalSection)
    IMPORT(306,RtlTryEnterCriticalSection)
    IMPORT(0xA0,KfRaiseIrql)
    IMPORT(0x81,KeRaiseIrqlToDpcLevel)
    IMPORT(24,ExQueryNonVolatileSetting)
    IMPORT(0xA1,KfLowerIrql)
	  // Data
    strcpy(environment->stringXbe,"XBE: ");
    strcpy(environment->stringEip,"EIP: 0x");
    strcpy(environment->stringEax,"EAX: 0x");
    strcpy(environment->stringEcx,"ECX: 0x");
    strcpy(environment->stringEdx,"EDX: 0x");
    strcpy(environment->stringEsp,"ESP: 0x");
    strcpy(environment->stringEbp,"EBP: 0x");
    strcpy(environment->stringEsi,"ESI: 0x");
    strcpy(environment->stringEdi,"EDI: 0x");
    strcpy(environment->stringExceptionFlags,"ExceptionFlags: 0x");
    strcpy(environment->stringExceptionCode,"ExceptionCode: 0x");
    strcpy(environment->stringExceptionRecord,"ExceptionRecord: 0x");
    strcpy(environment->stringCode,"Code: ");
    strcpy(environment->stringStack,"Stack: ");
    strcpy(environment->stringPrint,"Print: ");
    strcpy(environment->crash,"\\Device\\Harddisk0\\Partition1\\chihiro\\crash.txt");
    strcpy(environment->stringTimestamp,"<%10u,IRQL:%i,T:%X>: ");
    strcpy(environment->stringIn,"in: ");
    strcpy(environment->stringOut,"out: ");
    strcpy(environment->stringExQueryNonVolatileSettingArguments,"ExQueryNonVolatileSetting(0x%08X,0x%08X,0x%08X,0x%08X,0x%08X) = 0x");
    strcpy(environment->stringAvSendTVEncoderOptionArguments,"AvSendTVEncoderOption(0x%08X,0x%08X,0x%08X,0x%08X)");
    strcpy(environment->stringAvSetDisplayModeArguments,"AvSetDisplayMode(0x%08X,0x%08X,0x%08X,0x%08X,0x%08X,0x%08X) = 0x");
    strcpy(environment->stringWritePortArguments,"WritePort%c(0x%08X,0x%08X,%i)");
    strcpy(environment->stringReadPortArguments,"ReadPort%c(0x%08X,0x%08X,%i)");
    strcpy(environment->stringHalReadSMBusValueArguments,"HalReadSMBusValue(0x%08X,0x%08X,0x%08X,0x%08X) = 0x");
    strcpy(environment->stringHalWriteSMBusValueArguments,"HalWriteSMBusValue(0x%08X,0x%08X,0x%08X,0x%08X) = 0x");
    strcpy(environment->stringHalReadWritePCISpaceArguments,"HalReadWritePCISpace(0x%08X,0x%08X,0x%08X,0x%08X,0x%08X,%i)");
    strcpy(environment->stringHalReturnToFirmwareArguments,"HalReturnToFirmware(0x%08X)");
    strcpy(environment->stringKeInitializeDpcArguments,"KeInitializeDpc(0x%08X,0x%08X,0x%08X)");
    strcpy(environment->stringNtCreateFileArguments,"NtCreateFile(0x%08X,0x%08X,0x%08X ('%.*s'),0x%08X,0x%08X,0x%08X,0x%08X,0x%08X,0x%08X) = 0x");
    strcpy(environment->stringNtOpenFileArguments,"NtOpenFile(0x%08X,0x%08X,0x%08X ('%.*s'),0x%08X,0x%08X,0x%08X) = 0x");
    strcpy(environment->stringNtSetIoCompletionArguments,"NtSetIoCompletion(0x%08X,0x%08X,0x%08X,0x%08X,0x%08X) = 0x");
    strcpy(environment->stringRtlTryEnterCriticalSectionArguments,"RtlTryEnterCriticalSection(0x%08X) = ");
    strcpy(environment->stringRtlEnterCriticalSectionArguments,"RtlEnterCriticalSection(0x%08X)");
    strcpy(environment->stringRtlLeaveCriticalSectionArguments,"RtlLeaveCriticalSection(0x%08X)");
    strcpy(environment->stringKeRaiseIrqlToDpcLevelArguments,"KeRaiseIrqlToDpcLevel() = 0x");
    strcpy(environment->stringKfLowerIrqlArguments,"KfLowerIrql(0x%X)");
    strcpy(environment->stringKfRaiseIrqlArguments,"KfRaiseIrql(0x%X) = 0x");
    strcpy(environment->stringKeDelayExecutionThreadArguments,"KeDelayExecutionThread(0x%08X,0x%08X,0x%08X) = 0x");
  } else {
    environment = NULL; //TODO: Possibly return previous environment?
  }

#include "hookall.inc"

  // And hook the functions
  #define EXPORT(o,x) { exportAddressTableRva[o] = ((base==NULL)?he->x:((uintptr_t)base+(uintptr_t)hook##x-(uintptr_t)hookBase))-kernel; }
/*
0xA6
0x127
0x41
0x6C
0x123
0x9F
*/
  EXPORT(0xDB,NtReadFile)
  EXPORT(0x121,RtlInitAnsiString)
  EXPORT(0x63,KeDelayExecutionThread)
  EXPORT(50,HalWriteSMBusValue)
  EXPORT(45,HalReadSMBusValue)
  EXPORT(46,HalReadWritePCISpace)
  EXPORT(49,HalReturnToFirmware)
  EXPORT(329,READ_PORT_BUFFER_UCHAR)
  EXPORT(330,READ_PORT_BUFFER_USHORT)
  EXPORT(331,READ_PORT_BUFFER_ULONG)
  EXPORT(332,WRITE_PORT_BUFFER_UCHAR)
  EXPORT(333,WRITE_PORT_BUFFER_USHORT)
  EXPORT(334,WRITE_PORT_BUFFER_ULONG)
  EXPORT(2,AvSendTVEncoderOption)
  EXPORT(3,AvSetDisplayMode)
  EXPORT(107,KeInitializeDpc)
	EXPORT(190,NtCreateFile)
  EXPORT(202,NtOpenFile)
  EXPORT(227,NtSetIoCompletion)
  EXPORT(0x126,RtlLeaveCriticalSection)
  EXPORT(0x115,RtlEnterCriticalSection)
  EXPORT(306,RtlTryEnterCriticalSection)
  EXPORT(0xA0,KfRaiseIrql)
  EXPORT(0x81,KeRaiseIrqlToDpcLevel)
  // The following exports play a role in the whole hook foundation, they can not be disabled!
  EXPORT(24,ExQueryNonVolatileSetting)
  EXPORT(0xA1,KfLowerIrql)
	return environment;
}

void hookEnvironment(void) { return; }

// Anything from this point on will be overwritten with the environment at runtime!

//TODO: Merge with hook()
void installHook(void* base) {

	uintptr_t kernel = 0x80010000;
	uintptr_t kernelHeader = kernel + *(uint32_t*)(kernel+0x3C);	
	uintptr_t exportDirectoryTable = kernel + *(uint32_t*)(kernelHeader+0x78); //FIXME: This is pretty dirty?! going accross table borders etc - ignoring size?!
	uint32_t* exportAddressTableRva = kernel + *(uint32_t*)(exportDirectoryTable+0x1C);
	uint32_t ordinalBase = *(uint32_t*)(exportDirectoryTable+0x10);
	exportAddressTableRva = &exportAddressTableRva[-ordinalBase]; // Base offet

  size_t hookFunctionSize = (uintptr_t)hookEnvironment - (uintptr_t)hookBase;
  size_t hookEnvironmentSize = sizeof(HookEnvironment_t);
  size_t hookSize = hookFunctionSize + hookEnvironmentSize;

  memcpy(base,hookBase,hookFunctionSize);
  HookEnvironment_t* localHookEnvironment = (void*)((uintptr_t)base + hookFunctionSize);
//  memcpy(localHookEnvironment,&environment,hookEnvironmentSize);

  printf("hook: %i + %i bytes, memory at 0x%08X\n",hookFunctionSize,hookEnvironmentSize,base);
  printf("hookBase: %X %X\n",hookBase,hookBase()); //TODO: ASSERT

	// This can't be moved after creation!
//	RtlInitializeCriticalSection(&localHookEnvironment->critSect);
  
/*
  void(*hookCall)(void) = hook+(uintptr_t)test-(uintptr_t)hookBase;
  hookCall();
*/
  return;
}
