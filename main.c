/*
  
  Author: Jannik Vogel
  Date: 01/19/2014

  Documentation:

    http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3b-part-2-manual.pdf
    http://www.intel.com/Assets/ja_JP/PDF/manual/253668.pdf

  Done:

    - Set AGPBridge PCI prefetch limit to 128MB
    - Set MmAllocateContiguousMemoryEx highest page to 128MB
    - Set ARCADE and Unknown flag in XboxHardwareInfo
    - Mount filesystem
    - Roughly parse boot.id
    - Locate KiDebugRoutine
      - Find the current Stub / Trap
      - Patch it to jump to custom code [the KiDebugRoutine will be rewritten on quick reboot]
    - Kernel function hooking

  WIP:
    
    - Breakpoints to see where things go bad
    - Buffer output on my own and only write to disk on PASSIVE_LEVEL
    - Somehow hook or HLE the in / out instructions < done for up to 4 addresses at a time
      - Emulate Baseboard, possibly using dolphin as code base

  TODO (In no particular order, but research should always be first):
  
    - Cleanup
    - Release kernel memory on hook(NULL) / size back kernel
    - Commit "fix.h" changes back to OpenXDK
    - Automaticly create folders for "mbcom:" and "mbrom:"  
      - Possibly their own driver if they are even used
    - Decide for one prefetch technique, drop the rest
    - Fix/Workaround OpenXDK I/O timing/interrupt(?) problems
    - Possibly CHD installer
    - Menu using a "ROMS" folder and boot.id search
      - Alpha mixing
    - Preload XBE to cache partition and grab juicy details, possibly HLE it
    - Hook HalReturnToFirmware():
      - make sure we are only quick-rebooting..
      - ..unless returning to dashboard, in that case unhook it all
    - Hook the AV functions:
      - Interested in:
        - AV_OPTION_BLANK_SCREEN
        - AV_OPTION_MACROVISION_MODE
        - AV_OPTION_MACROVISION_COMMIT
        - AV_OPTION_ZERO_MODE
        - AV_OPTION_QUERY_MODE
        - AV_OPTION_ENABLE_LUMA_FILTER
        - AV_OPTION_CGMS
        - AV_OPTION_WIDESCREEN
        - AV_QUERY_AV_CAPABILITIES
        - AV_OPTION_QUERY_MODE
        - AV_QUERY_ENCODER_TYPE
        - AV_QUERY_MODE_TABLE_VERSION
    - Hook the SMBus functions and create a virtual eeprom
    - Move or at least check PFN address
    - Move or at least check instance pages

*/

/*
"\\??\\mbfs:" -> somewhere A
"\\Device\\CdRom0" -> somewhere A
"\\??\\mbcom:" -> somewhere B
"\\??\\mbrom:" -> somewhere C
*/

// LED flashing code from xbdev / xbox-linux - I don't get it to be honest..

#define LEDS(pwm) { \
  __asm__ volatile("movw $0xc004,%%dx\n" \
                   "mov $0x20, %%al\n" \
                   "out %%al, %%dx\n" \
                   \
                   "mov $0xc008, %%dx\n" \
                   "mov $8, %%al\n" \
                   "out %%al, %%dx\n" \
                   \
                   "mov $0xc006, %%dx\n" \
									 "mov %%cl,  %%al\n" \
                   "out %%al, %%dx\n" /* PWM Code at 0xC006 */ \
                   \
                   "mov $0xc000, %%dx\n" \
                   "in %%dx, %%ax\n" /* Read 0xC000 */ \
                   "out %%al, %%dx\n" /* Write 0xC000 ?! */ \
                   \
                   "mov $0xc002, %%dx\n" \
                   "mov $0x1a, %%al\n" \
                   "out %%al, %%dx" \
                   : \
                   :"c"(pwm) \
                   :"eax","edx"); \
}

#include <openxdk/openxdk.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <hal/input.h>
#include <hal/video.h>
#include <hal/xbox.h>
#include <hal/io.h>
#include <hal/fileio.h>

#include <string.h>

#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define PCI_SLOT(device, function) (((function) << 5) | (device))

#include "common/x86Types.h"
#include "common/x86Encode.h"
#include "common/x86.h"
#include "fix.h"
#include "mount.h"
#include "launch.h"
#include "font.h"
#include "pci.h"
#include "patch.h"
#include "blitter.h"

#include "hook.h"

typedef struct {
  char magic[4];
  uint8_t unk7[0xC];
  //32 bit: 480 (something to do with resolution?)
  //32 bit: 1
  //32 bit: 1
  uint8_t pad[0x10];

  char xbam[4]; //Xbox arcade [/amusement?] machine?
  uint8_t unk6[4];
  uint16_t unkYear; //0x28: 16 bit: year of xbamgd.bin release? 2002
  uint8_t unkDay;
  uint8_t unkMonth;
  uint8_t unk8[4]; //xbam version?

  char gameId[8]; //0x30: GameID
  uint8_t unk9[0x28];
  char maker[0x20]; //0x60: maker?
  char title[0x20]; //0x80: title
  char gameXbe[0x20]; //0xA0: game xbe
  char testXbe[0x20]; //0xC0: test xbe
  // The following ones are either zero terminated OR the first symbol is checked for 0x00
  char startCredits[0x20]; //0xE0: test mode option 1? Maybe DIPSW settings?
  char continueCredits[0x20]; //0x100: test mode option 2?
  char unk0[0x20]; //0x120: test mode option 3?
  char unk1[0x20]; //0x140: test mode option 4?
  char unk2[0x20]; //0x160: test mode option 5?
  char unk3[0x20]; //0x180: test mode option 6?
  char unk4[0x20]; //0x1A0: test mode option 7?
  char unk5[0x20]; //0x1C0: test mode option 8?
} __attribute__((packed)) bootId_t;


//bus << 16  |  device << 11  |  function <<  8  |  offset

uint32_t getPrefetchLimit3(void) {
  //bus << 16  |  device << 11  |  function <<  8  |  offset
  IoOutputDword(0xCF8,(1 << 31) | (30 << 11) | 0x24);
  return IoInputDword(0xCFC) >> 16;
}

uint32_t getPrefetchLimit1(void) {
  uint32_t buffer;
  HalReadWritePCISpace(0,PCI_SLOT(30,0),0x24,&buffer,4,0);
  return buffer >> 16;
}

uint16_t getPrefetchLimit2(void) {
  uint16_t buffer;
  HalReadWritePCISpace(0,PCI_SLOT(30,0),0x26,&buffer,2,0);
  return buffer;
}

void setPrefetchLimit1(uint16_t limit) {
  HalReadWritePCISpace(0,PCI_SLOT(30,0),0x26,&limit,2,1); // did not work!
  return;
}

void setPrefetchLimit2(uint16_t limit) {
  uint32_t buffer;
  HalReadWritePCISpace(0,PCI_SLOT(30,0),0x24,&buffer,4,0);
  buffer = (limit << 16) | (buffer & 0xFFFF);
  HalReadWritePCISpace(0,PCI_SLOT(30,0),0x24,&buffer,4,1); // worked!
  return;
}

void setPrefetchLimit3(uint16_t limit) {
  IoOutputDword(0xCF8,(1 << 31) | (30 << 11) | 0x24);
  uint32_t buffer = IoInputDword(0xCFC);
  buffer = (limit << 16) | (buffer & 0xFFFF);
  IoOutputDword(0xCFC,buffer); // worked!
  return;
}


#if 0
void* createDR(void) {

  void* base = MmAllocateContiguousMemory(0x1000);
  if (base == NULL) {
    printf("couldn't get memory for handler!\n");
    return NULL;
  }
  MmSetAddressProtect(base,0x1000,PAGE_EXECUTE_READWRITE);
  memcpy(base,drfunc,0x1000);
  MmPersistContiguousMemory(base,0x1000,TRUE);
  printf("Got memory at 0x%08X!\n",(uintptr_t)base);
  return base;

}
#endif



static KIRQL safemodeIrql;

void enableSafemode(void) {

	safemodeIrql = KeRaiseIrqlToDpcLevelFix();

	disableInterrupts();
//  disableCache();
  disableWriteProtect();

  flushCache();
  flushTlb();

	return;
	
}

void disableSafemode(void) {

  flushTlb();
  flushCache();

  enableWriteProtect();
//  enableCache();
  enableInterrupts();

  KfLowerIrqlFix(safemodeIrql);

	return;
}

void XBoxStartup(void) {

//TODO: Reboot if saveddataaddress is != 0?!
  //TODO: move to fix.h?
  MmQueryAddressProtectFix = (void*)&MmQueryAddressProtect;
  KeRaiseIrqlToDpcLevelFix = (void*)&KeRaiseIrqlToDpcLevel;
  KfLowerIrqlFix = (void*)&KfLowerIrql;

  FILE* f = fopen("E:\\chihiro\\log.txt","w");
  fprintf(f,"Failed to log!\n");
  fclose(f);

  f = fopen("E:\\chihiro\\crash.txt","w");
  fclose(f);

  freopen ("E:\\chihiro\\log.txt", "w", stdout);

//patchheaders();
void* kernelsp = resizeKernel();


//pcidump();


//void* handler = createDR();

uintptr_t data = (uintptr_t)&KeTickCount;
PKDEBUG_ROUTINE* ptrKiDebugRoutine = (PKDEBUG_ROUTINE*)(data+64);

{ 
  printf("Debug routine supposed to be at 0x%08X, KdDebuggerEnabled: 0x%08X\n",*ptrKiDebugRoutine,KdDebuggerEnabled);
//  *KiDebugRoutine = debugRoutine;

/*
  HalWriteSMBusValue(0x20, 0x08, FALSE, (0x0 << 4) | 0x8); // Red PWM | Green PWM
  HalWriteSMBusValue(0x20, 0x07, FALSE, 0x01); // Overwrite
  XSleep(1000);
*/

  // Crash me!
//  asm("int3");
//  XSleep(1000);

/*
  HalWriteSMBusValue(0x20, 0x08, FALSE, (0x8 << 4) | 0x0); // Red PWM | Green PWM
  HalWriteSMBusValue(0x20, 0x07, FALSE, 0x01); // Overwrite
  XSleep(1000);
*/



/*
  *KiDebugRoutine = (uintptr_t)handler;
  BOOLEAN* KdDebuggerEnabledFix = &KdDebuggerEnabled;
  *KdDebuggerEnabledFix = TRUE; // This should protect us from being overwritten
  printf("Debug routine now at 0x%08X, KdDebuggerEnabled: 0x%08X\n",*KiDebugRoutine,KdDebuggerEnabled);
*/



enableSafemode();

	if (kernelsp == NULL) {
		printf("Couldn't get any kernel space!\n");
	} else {

#if 0
	// Install handler
	memcpy(kernelsp,drfunc,0x2000);
	TRANSPORT transport = {
		  HalWriteSMBusValue
	};
	TRANSPORT* transportData = ((uintptr_t)kernelsp)+0x1500;
	memcpy(transportData,&transport,0xB00);
#endif

  installHook(kernelsp);






	uintptr_t addr = (uintptr_t)*ptrKiDebugRoutine; // Get the stub

	uint8_t* code = (uint8_t*)addr;
#if 0
	setPopEax((void*)&code[0]);
	setPush((void*)&code[1],transportData);
	setPushEax((void*)&code[6]);
	setJump((void*)&code[7],kernelsp);
#else
  encodeJmp((void*)&code[0],(uintptr_t)kernelsp+(uintptr_t)hookKiDebugRoutine-(uintptr_t)hookBase);
#endif

  code = (void*)&KeBugCheckEx;
  encodeJmp((void*)&code[0],(uintptr_t)kernelsp+(uintptr_t)hookKeBugCheckEx-(uintptr_t)hookBase);

HookEnvironment_t* hookEnvironment = hook(kernelsp);



uint16_t cs = getCs();
printf("CS: 0x%04X\n",cs);
uint16_t ds = getDs();
printf("DS: 0x%04X\n",ds);
uint16_t ss = getSs();
printf("SS: 0x%04X\n",ss);
uint16_t tr = getTr();
printf("TR: 0x%04X\n",tr);

// Retrieve the GDT
uint16_t gdtLimit;
uint32_t gdtBase;
getGdt(&gdtLimit,&gdtBase);

// Locate the descriptors
GdtDescriptor_t* csDescriptor= (GdtDescriptor_t*)(gdtBase+cs);
GdtDescriptor_t* dsDescriptor= (GdtDescriptor_t*)(gdtBase+ds);
GdtDescriptor_t* ssDescriptor= (GdtDescriptor_t*)(gdtBase+ss);
GdtDescriptor_t* trDescriptor= (GdtDescriptor_t*)(gdtBase+tr);

// Locate the TSS
Tss_t* tss = (Tss_t*)((trDescriptor->baseFF000000 << 24) | trDescriptor->base00FFFFFF);

// Create temporary GDT
//NOTE: Allocated here because kernel calls won't be available soon
void* temporaryGdt = MmAllocateContiguousMemory(gdtLimit+sizeof(GdtDescriptor_t));

// This is a TSS which will just return when jumped to
Tss_t* temporaryTss = MmAllocateContiguousMemory(sizeof(Tss_t));
memcpy(temporaryTss,tss,sizeof(Tss_t));
temporaryTss->eip = (uintptr_t)iretLoop;
//FIXME: Setup ESP and EFLAGS?

// Append our own descriptor for a TSS we can switch to, to force a reload of the TSS
//NOTE: We overwrote some random kernel variable here! Don't do anything with kernel!
GdtDescriptor_t* temporaryTrDescriptor = (GdtDescriptor_t*)((uintptr_t)gdtBase+gdtLimit);
GdtDescriptor_t backup;
memcpy(&backup,temporaryTrDescriptor,sizeof(GdtDescriptor_t));
memcpy(temporaryTrDescriptor,trDescriptor,sizeof(GdtDescriptor_t));
temporaryTrDescriptor->busy = 0;
temporaryTrDescriptor->baseFF000000 = (uintptr_t)temporaryTss >> 24;
temporaryTrDescriptor->base00FFFFFF = (uintptr_t)temporaryTss;

// Copy the original GDT to our temporary copy and activate it
/*
	setGdt(gdtLimit+sizeof(GdtDescriptor_t),gdtBase);
	lcall(gdtLimit,0); 
*/
memcpy(temporaryGdt,(void*)gdtBase,gdtLimit+sizeof(GdtDescriptor_t));
setGdt(gdtLimit+sizeof(GdtDescriptor_t),(uintptr_t)temporaryGdt);
lcall(gdtLimit,0);

// Create our new TSS
memcpy(&hookEnvironment->tss,tss,sizeof(Tss_t)); // Copy data which is not stored on task switch
memset(&hookEnvironment->iomap[0x0000/8],0x00,0x4000/8); // 0x0000 - 0x3FFF accessible
memset(&hookEnvironment->iomap[0x4000/8],0xFF,0x100/8); // 0x4000 - 0x4100 not accessible, anything above is accessible by default

// Modify the original TR Descriptor to point at the new TSS
trDescriptor->privilege = 1;
trDescriptor->baseFF000000 = (uintptr_t)&hookEnvironment->tss >> 24; 
trDescriptor->base00FFFFFF = (uintptr_t)&hookEnvironment->tss; 
trDescriptor->limitF0000 = (sizeof(hookEnvironment->tss)+sizeof(hookEnvironment->iomap)) >> 16;
trDescriptor->limit0FFFF = (sizeof(hookEnvironment->tss)+sizeof(hookEnvironment->iomap));

// Modify CS, DS and SS Descriptor to work on higher privilege level
csDescriptor->privilege = 0;
dsDescriptor->privilege = 0;
ssDescriptor->privilege = 0;

// Switch to the extended original GDT
setGdt(gdtLimit+sizeof(GdtDescriptor_t),gdtBase);
lcall(gdtLimit,0);

// Now we are running the original TSS again. Remove descriptor and restore backup
setGdt(gdtLimit,gdtBase);
memcpy(temporaryTrDescriptor,&backup,sizeof(GdtDescriptor_t));

// Free temporary TSS and GDT
MmFreeContiguousMemory(temporaryTss);
MmFreeContiguousMemory(temporaryGdt);

printf("TR: 0x%X, Original-Type: 0x%X\n",getTr(),trDescriptor->type);
printf("TSS/TR-Limit: 0x%05X\n",(trDescriptor->limitF0000 << 16) | trDescriptor->limit0FFFF);
printf("TSS/TR-Base: 0x%08X\n",(trDescriptor->baseFF000000 << 24) | trDescriptor->base00FFFFFF);


	}


  
}

/*
LEDS(0x00)
XSleep(2000);
//FIXME: Lower IOPL to 0
asm("pushfl\n"
		"pop %%eax\n"
		"and $0xFFFFCFFF,%%eax\n"
		"push %%eax\n"
		"popfl\n":::"eax");
LEDS(0xFF)
XSleep(2000);
*/

disableSafemode();


//FIXME: Set CPL to 1
LEDS(0xF0)
XSleep(500);
__asm__ __volatile__("cli\n"
 										 "pushfl\n" 
										 "andl $0xFFFFBFFF, (%%esp)\n"// Remove NT
										 "popfl\n"
										 "mov %%esp,%%esi\n"
/*
		  							 "push %%eax\n" // SS
										 "push %%esi\n" // ESP
*/
										 "pushfl\n" // EFLAGS
										 "orl $0x200, (%%esp)\n" // Enable interrupts after iret
										 "push %%edx\n" // CS
										 "push $target\n" //EIP
								     "mov %%bx,%%ds\n" 
										 "iret\n"
										 "target:"
										 :
//							 			 :"d"(getCs()|0),"a"(getSs()|1),"b"(getDs()|1)
										 :"d"(getCs()),"a"(getSs()),"b"(getDs())
										 :"esi");
LEDS(0x00)
//while(1);

installIoDebugger();
/*
DWORD type;
//UCHAR region;
uint32_t region;
SIZE_T xlength;
NTSTATUS status = ExQueryNonVolatileSetting(XC_FACTORY_GAME_REGION,
                                       &type,
                                       &region,
                                       4,
                                       &xlength); // < should be 4
*/

  XVideoSetMode(640, 480, 32, 60);
  XVideoSetSoftenFilter(0);
  XVideoSetFlickerFilter(0);

  void* fb = XVideoGetFB();
  void* pb = (BYTE*)malloc(640*480*4);

  float last = (float)KeTickCount;
  int   fps  = 0;

  XInput_Init();

  printf("Found %i pad(s)\n",XInputGetPadCount());

printf("Flags were: 0x%08X GPU: 0x%X, MCP: 0x%X\n",XboxHardwareInfo.Flags,XboxHardwareInfo.Unknown1,XboxHardwareInfo.Unknown2);
XBOX_HARDWARE_INFO* x = (XBOX_HARDWARE_INFO*)XboxHardwareInfo.Flags;
//printf("Flags were: 0x%08X...\n",x->Flags);
bool wasDevkit = (XboxHardwareInfo.Flags & 0x00000001);
bool wasArcade = (XboxHardwareInfo.Flags & 0x00000008);
XboxHardwareInfo.Flags |= 0x00000008; // Arcade
bool wasFlagPatched = (XboxHardwareInfo.Flags & 0x00000100);
XboxHardwareInfo.Flags |= 0x00000100; // Prevents CdRom from being remapped
printf("Flags are: 0x%08X (0x%08X)\n",XboxHardwareInfo.Flags,&XboxHardwareInfo);

bool devkit = false;
bool hackMemory = false;
bool canHackMemory = false;
bool wasMemoryHacked = false;
uint8_t seq1[] = { 0xba,0xdf,0x3f,0x00,0x00 };
uint8_t seq2[] = { 0xba,0xcf,0x7f,0x00,0x00 };
uint8_t* ptr = (uint8_t*)MmAllocateContiguousMemoryEx;
unsigned int size = (uintptr_t)MmFreeContiguousMemory - (uintptr_t)MmAllocateContiguousMemoryEx;
printf("Searching for hack in MmAllocateContiguousMemoryEx (%i bytes)\n",size);
if (size < 10000) {
  int i;
  for(i = 0; i < size; i++) {
    if (!memcmp(ptr,seq1,sizeof(seq1))) {    
      ptr++;
      printf("Limit is at 0x%08X\n",*(uint32_t*)ptr);
      canHackMemory = true;
      break;
    }
    if (!memcmp(ptr,seq2,sizeof(seq2))) {
      ptr++;
      printf("Limit is at 0x%08X\n",*(uint32_t*)ptr);
      canHackMemory = true;
      wasMemoryHacked = true;
      break;
    }
    ptr++;
  }
  if (i == size) {
    printf("Limit not found!\n");
  }
} else {
  printf("Function too large!\n");
}

  uint32_t low,high;

  bool wasWritebackPatched;
  bool wasPrefetchPatched;
  bool wasFallbackPatched = ((rdmsr(0x2FF,&high,&low) & 0xFF) == 6); // Check MTR

  disableInterrupts();
  disableCache();
  flushCache();
  flushTlb();
  wrmsr(0x2FF,0,0); // Disable MTRR

  char* mtrrdump = malloc(4096);
  *mtrrdump = '\0';

  int i;

  char* types[] = {
    "UnCachable","WriteCombined","*","*","WriteThrough","WriteProtect","WriteBack"
  };

  for(i = 0; i < 8; i++) {
    uint64_t va = rdmsr(0x200+i*2,&high,&low);  
    uint64_t vb = rdmsr(0x201+i*2,&high,&low);
    uint8_t type = va & 0xFF;
    uint32_t base = (va>>12) << 12;
    uint32_t mask = (vb>>12) << 12;

    sprintf(&mtrrdump[strlen(mtrrdump)],"MTRR %i: 0x%08X - 0x%08X (%x = %s)\n",i,base,~mask|base,type,types[type]);
//    sprintf(&mtrrdump[strlen(mtrrdump)],"MTRR 0x%X: 0x%08X - 0x%08X (0x%X: %s)\n",i,((va>>12)<<12),~((vb>>12)<<12) | ((va>>12)<<12),va&0xFF,"Unk");
  }
  printf(mtrrdump);

  {    

    // Read limits
    wasPrefetchPatched = (getPrefetchLimit2() == 0xF7F0);
    printf("Prefetch limit is 0x%04X\n",getPrefetchLimit2());
    rdmsr(0x201,&high,&low);
    wasWritebackPatched = (low == 0xF8000800);
    printf("Writeback limit is 0x%08X%08X\n",high,low);

    // Push limits
    setPrefetchLimit2(0xF7F0);
  //TODO: Host bridge memory top?
    low = 0xF8000800; // 128MB, originally 0xFC000800 (64MB)
    wrmsr(0x201,high,low); // MTRR for WB memory

/*
  0x0000000FF8000800 //0xFF8000 = 128MB
  0x0000000FFC000800 //0xFFC000 = 64MB
*/

    // Read limits
    printf("Prefetch limit is 0x%04X\n",getPrefetchLimit2());
    rdmsr(0x201,&high,&low);
    printf("Writeback limit is 0x%08X%08X\n",high,low);

  }

  wrmsr(0x2FF,0,0x800); // Enable MTR
  enableCache();
  enableInterrupts();

  uint8_t top;
  HalReadWritePCISpace(0, PCI_SLOT(0,0), 0x87, &top, 1, 0);

  MM_STATISTICS memoryStatistics;
  memoryStatistics.Length = sizeof(MM_STATISTICS);
  MmQueryStatistics(&memoryStatistics);




/*
// This does not do what we want :/
void* p = MmMapIoSpace(0x4000,0x100,PAGE_READWRITE);
printf("IO Mapping: 0x%X\n",(unsigned int)p);
*/

// Test hardware access.. if this doesn't crash we won't be running into too many problems probably
#if 0
printf("Read 0x%08X\n",IoInputDword(0x401F));
printf("Read 0x%08X\n",IoInputDword(0x401E));
IoOutputDword(0x4080,0xDEADBEEF);

IoOutputDword(0x4084,0xDEADBEEF);
printf("Wrote\n");
printf("Read 0x%08X\n",IoInputDword(0x4088));
#endif

//printf("Opening cdrom: %i\n",ObOpenObjectByName());

#if 0
#if 0
uint8_t* ptr = (uint8_t*)MmAllocateContiguousMemoryEx;
unsigned int size = (uintptr_t)MmFreeContiguousMemory - (uintptr_t)MmAllocateContiguousMemoryEx;
printf("Dumping MmAllocateContiguousMemoryEx (%i bytes)\n",size);
if (size > 10000) { size = 10000; } 
for(int i = 0; i < size; i++) {
  if (i % 0x10 == 0) {
    printf("\n0x%08X: ",ptr);
    XSleep(1); // IO Sucks in OXDK.. stuff gets lost all the time 
  }
  printf("%02X",*ptr++);
}
printf("\n");
#else
FILE* fx = fopen("MmAllocateContiguousMemoryEx.bin","wb");
fwrite(MmAllocateContiguousMemoryEx,1,size,fx);
fclose(fx);
#endif
#endif

  bool test;
  bool mame;
  
  while(1) {

    static int t = 30*10*100; //FIXME: Change back
    if (t-- <= 0) {
      break;
    }

    XInput_GetEvents();

    test = (g_DefaultPad.CurrentButtons.ucAnalogButtons[XPAD_A] > 16);
    mame = (g_DefaultPad.CurrentButtons.ucAnalogButtons[XPAD_B] > 16);
    hackMemory = (g_DefaultPad.CurrentButtons.ucAnalogButtons[XPAD_X] > 16);
    devkit = (g_DefaultPad.CurrentButtons.ucAnalogButtons[XPAD_Y] > 16);

    // This sounds like fun!
    {
      if (g_DefaultPad.CurrentButtons.ucAnalogButtons[XPAD_WHITE] > 16) {
        asm("int3");
      }
      if (g_DefaultPad.CurrentButtons.ucAnalogButtons[XPAD_BLACK] > 16) {
        int i;
        for(i = 0; i < 1000; i++) {
          *(uint32_t*)rand() = rand();
        }
      } 
      if (g_DefaultPad.CurrentButtons.usDigitalButtons & XPAD_RIGHT_THUMB) {
        LEDS(0x0F);
      } 
      if (g_DefaultPad.CurrentButtons.usDigitalButtons & XPAD_LEFT_THUMB) {
        EXCEPTION_RECORD ExceptionRecord;
        ExceptionRecord.ExceptionCode = 0xBABE;
        (*ptrKiDebugRoutine)(NULL,NULL,&ExceptionRecord,NULL,TRUE);
      } 
    }

    if (g_DefaultPad.CurrentButtons.usDigitalButtons & XPAD_START) {
      break;
    } 

    if (g_DefaultPad.CurrentButtons.usDigitalButtons & XPAD_BACK) {
      goto cleanup;
    } 




      
    // Clear screen
//    memset(pb,x++%2?0xFF:0x00,640*480*4);
/*
    fill((uint8_t*)pb,0,0,640,240,chihiro?0x00FF00:0xFF0000);
    fill((uint8_t*)pb,0,240,640,240,0x000000);
*/

    fill((uint8_t*)pb,0,0,640,480,0x000000);
  
    int i = 0;
    drawBoolean((uint8_t*)pb,20,20+i++*20,2,"Prefetch","Yes","No",wasPrefetchPatched);
    drawBoolean((uint8_t*)pb,20,20+i++*20,2,"Writeback","Yes","No",wasWritebackPatched);
    drawBoolean((uint8_t*)pb,20,20+i++*20,2,"Cache fallback","Yes","No",wasFallbackPatched);
    drawBoolean((uint8_t*)pb,20,20+i++*20,2,"Arcade","Yes","No",wasArcade);
    drawBoolean((uint8_t*)pb,20,20+i++*20,2,"Devkit","Yes","No - Boot a debug bios!",wasDevkit);
    drawBoolean((uint8_t*)pb,20,20+i++*20,2,"Unknown mount flag","Yes","No",wasFlagPatched);
    if (canHackMemory) {
      drawBoolean((uint8_t*)pb,20,20+i++*20,2,"Memory hacked","Yes","No",wasMemoryHacked);
    }


    char buffer[200];

    sprintf(buffer,"Memory: %iMB (%i pages / %iMB)",((top+1)*0x1000000)/(1024*1024),memoryStatistics.TotalPhysicalPages,memoryStatistics.TotalPhysicalPages*0x1000/(1024*1024));
    drawText((uint8_t*)pb,20,40+i++*20,2,buffer,0xFFFFFF,0xFF000000);
    PXBOX_KRNL_VERSION version = (PXBOX_KRNL_VERSION)&XboxKrnlVersion;
    sprintf(buffer,"K: %i.%i.%i.%i, GPU: 0x%X, MCP: 0x%X\n",version->Major,version->Minor,version->Build,version->Qfe,XboxHardwareInfo.Unknown1,XboxHardwareInfo.Unknown2);
    drawText((uint8_t*)pb,20,40+i++*20,2,buffer,0xFFFFFF,0xFF000000);
    if (canHackMemory) {
      sprintf(buffer,"Highest page: 0x%08X\n",*(uint32_t*)ptr);
      drawText((uint8_t*)pb,20,40+i++*20,2,buffer,0xFFFFFF,0xFF000000);
    }


/*
void
AvSendTVEncoderOption(
    IN  PVOID RegisterBase,
    IN  ULONG Option,
    IN  ULONG Param,
    OUT PULONG Result
    )

AV_QUERY_ENCODER_TYPE
AV_ENCODER_FOCUS
AV_ENCODER_CONEXANT_871

AV_QUERY_AV_CAPABILITIES

*/

    sprintf(buffer,"Compile time: " __TIME__ " (" __DATE__ ")\n\n"
                   "Hold A for Testmode: %s\n"
                   "Hold B for MAME Hack: %s\n"
                   "Hold X for Memory Hack: %s\n"
                   "Hold Y for Devkit fake: %s\n"
                   "Press Start to launch (Timeout: %i)\n"
                   "Press Back to exit\n\n%s",
                   test?"Test mode":"Game mode",mame?"Yes":"No",canHackMemory?(hackMemory?"Yes":"No"):"Error!",devkit?"Yes":"No",t/30,mtrrdump);
    drawText((uint8_t*)pb,20,60+i++*20,1,buffer,0xFFFFFF,0xFF000000);

    // Sync and Flip
    XVideoWaitForVBlank();
    memcpy(fb, pb, 640*480*4);

  }

if (mame) {
  wrmsr(0x2FF,0,0x806); // Enable MTRR with MAME hack..
}

if (devkit) {
  XboxHardwareInfo.Flags |= 0x00000001; // Devkit
}

if (canHackMemory && hackMemory) {
  void* base = (void*)(((uintptr_t)ptr) & 0xFFFFF000);
/*
  NTSTATUS(*NtProtectVirtualMemoryFix)(IN OUT PVOID *BaseAddress,IN OUT PSIZE_T RegionSize,IN ULONG NewProtect,OUT PULONG OldProtect) = &NtProtectVirtualMemory;
*/

/*
ULONG prot;
PVOID addr = ptr;
  int ret = NtProtectVirtualMemoryFix(&addr,&nsize,PAGE_EXECUTE_READWRITE,&prot);
printf("0x%X: Old protection was 0x%08X\n",ret,prot);
*/

KIRQL l = KeRaiseIrqlToDpcLevelFix();
disableInterrupts();

//  SIZE_T nsize = size;

  uint32_t prot = MmQueryAddressProtectFix(base);
  printf("Protection was 0x%08X at 0x%08X (base: 0x%08X)\n",prot,(uintptr_t)ptr,(uintptr_t)base);
  MmSetAddressProtect(base,0x2000,PAGE_READWRITE);
  uint32_t prot3 = MmQueryAddressProtectFix(base);
  printf("Protection was 0x%08X at 0x%08X (base: 0x%08X)\n",prot3,(uintptr_t)ptr,(uintptr_t)base);

disableCache();
flushCache();

*(uint32_t*)ptr = 0x00007FCF;
//*(uint32_t*)ptr = 0x00002FCF;

flushTlb();
enableCache();


//  ULONG prot2;
//  NtProtectVirtualMemoryFix(&addr,&nsize,prot,&prot2);
  MmSetAddressProtect(base,0x2000,prot);
  printf("Memory after hack: 0x%08X\n",*(uint32_t*)ptr);

enableInterrupts();
KfLowerIrqlFix(l);


}






  printf("Getting launcher path\n");
  char launcherPath[256]; 
  int ret = XConvertDOSFilenameToXBOX((char*)".\\",launcherPath);
  printf("%i: Got launcher path: %s\n",ret,launcherPath);
//  goto cleanup;

  char bootIdPath[256];
//  sprintf(bootIdPath,"%s%s",launcherPath,"boot.id");
  strcpy(bootIdPath,".\\boot.id");
  
  bootId_t bid;
  
  FILE* bin = fopen(bootIdPath,"rb"); //TODO: Wrap fopen so that fopen first converts an xbox path to dos path only so that openxdk can convert it back..
  if (bin == NULL) {
    printf("Failed to open %s\n",bootIdPath);
    goto cleanup;
  }  
  fseek(bin,0,SEEK_END);  
  size_t length = ftell(bin);
  if (length != sizeof(bootId_t)) {
    printf("File wasn't of correct size (Got %i bytes, expected %i bytes) - maybe not a boot.id?\n",length,sizeof(bootId_t));
    fclose(bin);
//    return 1;
    goto cleanup;
  }
  fseek(bin,0,SEEK_SET);  
  printf("Now at %i\n",ftell(bin));
  fread(&bid,1,length,bin);
  fclose(bin);
  
  char MediaboardFsPath[256];
  char MediaboardRomPath[256];  
  char MediaboardComPath[256];
  XConvertDOSFilenameToXBOX((char*)"E:\\chihiro\\mbrom\\",MediaboardRomPath);
  XConvertDOSFilenameToXBOX((char*)"E:\\chihiro\\mbcom\\",MediaboardComPath);
//  XConvertDOSFilenameToXBOX(launcherPath,MediaboardFsPath);
  strcpy(MediaboardFsPath,launcherPath);

  char launchPath[256] = { 0 };
  strcpy(launchPath,launcherPath);
  launchPath[strlen(launchPath)-1] = '\0';
  strcat(launchPath,test?bid.testXbe:bid.gameXbe);

//strcpy(launchPath,"E:\\chihiro\\chihiro-loader-1.xbe");

  printf("Launching '%.32s' at '%s'\n",bid.title,launchPath);

  // Remount the filesystem to be more like a real chihiro

  unmount("\\??\\D:");
  //deleteDevice("\\Device\\CdRom0"); // Not sure about the API yet..
  printf("Unmounted D: and Disc Drive\n");  

  printf("Mounting '%s' to Disc Drive and Mediaboard Filesystem\n",MediaboardFsPath);
  mount("\\??\\mbfs:",MediaboardFsPath);
  //mount("\\Device\\CdRom0",MediaboardFsPath); // Can't be done because we can't delete the device yet
  mount("\\??\\D:",MediaboardFsPath); // Best we can do for now :(
  printf("Mounting '%s' to Mediaboard Communication\n",MediaboardComPath);
  mount("\\??\\mbcom:",MediaboardComPath);
  printf("Mounting '%s' to Mediaboard ROM\n",MediaboardRomPath);
  mount("\\??\\mbrom:",MediaboardRomPath);

/*
    if ( NtOpenSymbolicLinkObject(&a1, &v15) < 0
      || (v19 = &v13, v18 = 0x2080000u, v4 = NtQuerySymbolicLinkObject(a1, &v18, 0), NtClose(a1), v4 < 0) )
*/

cleanup:

  printf("Exit!\n");

  free(pb);
  XInput_Quit();

  fclose(stdout);

	LEDS(0x00);
  
  if (launchPath[0] != '\0') {
    uint8_t* data = malloc(3072);
    memset(data,0x00,3072);
    *(uint32_t*)data = 1;
    launch(launchPath,1,(void*)data);
    free(data);
  }

  // Turn LED orange to signalize error condition

  HalWriteSMBusValue(0x20, 0x08, FALSE, (0xF << 4) | 0xF); // Red PWM | Green PWM
  HalWriteSMBusValue(0x20, 0x07, FALSE, 0x01); // Overwrite

  XSleep(1000);

HalReturnToFirmware(ReturnFirmwareQuickReboot); //FIXME: Comment out
  XReboot();

}

