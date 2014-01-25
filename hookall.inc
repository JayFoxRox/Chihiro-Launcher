
// Generic hook to notify us about all functions
{

  unsigned int ordinal;
  for(ordinal = ordinalBase; ordinal <= 366; ordinal++) { //FIXME: Push if import table is long enough

    // Detect and avoid constants / variables

  #define CONSTANT(s,o) { if ((o) == ordinal) { continue; }}
    CONSTANT(ExEventObjectType,16)
    CONSTANT(ExMutantObjectType,22)
    CONSTANT(ExSemaphoreObjectType,30)
    CONSTANT(ExTimerObjectType,31)
    CONSTANT(HalBootSMCVideoMode,356)
    CONSTANT(HalDiskCachePartitionCount,40)
    CONSTANT(HalDiskModelNumber,41)
    CONSTANT(HalDiskSerialNumber,42)
    CONSTANT(IdexChannelObject,357)
    CONSTANT(IoCompletionObjectType,64)
    CONSTANT(IoDeviceObjectType,70)
    CONSTANT(IoFileObjectType,71)
    CONSTANT(KdDebuggerEnabled,88)
    CONSTANT(KdDebuggerNotPresent,89)
    CONSTANT(KeInterruptTime,120)
    CONSTANT(KeSystemTime,154)
    CONSTANT(KeTickCount,156)
    CONSTANT(KeTimeIncrement,157)
    CONSTANT(KiBugCheckData,162)
    CONSTANT(LaunchDataPage,164)
    CONSTANT(MmGlobalData,102)
    CONSTANT(ObDirectoryObjectType,240)
    CONSTANT(ObpObjectHandleTable,245)
    CONSTANT(ObSymbolicLinkObjectType,249)
    CONSTANT(PsThreadObjectType,259)
    CONSTANT(XboxAlternateSignatureKeys,354)
    CONSTANT(XboxEEPROMKey,321)
    CONSTANT(XboxHardwareInfo,322)
    CONSTANT(XboxHDKey,323)
    CONSTANT(XboxLANKey,353)
    CONSTANT(XboxKrnlVersion,324)
    CONSTANT(XboxSignatureKey,325)
    CONSTANT(XeImageFileName,326)
    CONSTANT(XePublicKeyData,355)

    // So this is a function

    uint32_t* p = &exportAddressTableRva[ordinal];
    uint8_t* code = &environment->code[8*(ordinal-ordinalBase)];

    if (*p == 0x00000000) { continue; } // Unused entry?

    if (base != NULL) {
      uint32_t original = *p + kernel;
      encodeInt3(&code[0]);
      encodeJmp(&code[1],original);
      encodeInt3(&code[6]); // For this part to work you also have to modify the ret address before the jmp..
      encodeRet(&code[7]);
      *p = (uintptr_t)code - kernel;
    } else {
      if ((code[0] == 0xCC) && (code[1] == 0xE9)) { // For call this has to be 0xE8
        uint32_t address = &code[1];
        uint32_t target = *(uint32_t*)&code[2];
        uint32_t original = target+address+5;
        *p = original - kernel;
      }
    }

    // Next ordinal
  
  }

}
