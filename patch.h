// Ported from nkpatcher source!

/*
struc			KERNEL_INFO
.version:		resd 1
.patcher:		resd 1
.bootflags_addr:		resd 1
.top_var_addr:		resd 1
.expansion_size:		resd 1
.kernel_move_saved_data:	resd 1
.ldr1_space:		resd 1
.ldr2_space:		resd 1
.sign_space:		resd 1
.mvis_space:		resd 1
.expd_space:		resd 1
.ldr1_space_end:		resd 1
.ldr2_space_end:		resd 1
.sign_space_end:		resd 1
.mvis_space_end:		resd 1
.expd_space_end:		resd 1
endstruc
*/

const int KI_expansion_size = 0xA000;

/*
	dd %1, patcher_%1, %2, %3, (USEDSPACE_EXPD_%1 + 0xFFF) & ~0xFFF, %4, \
            //XXXX Version
            //      XXXXXXXXX bootflags
            //                 XXXXXXXXX top_var_addr
            //                            XXXXXXXXX kernel_move_saved_data
	kinfo_entry 3944, 8003BE58h, 8003bff0h, 80031656h
	kinfo_entry 4034, 8003BF18h, 8003c0b0h, 80031293h
	kinfo_entry 4817, 8003B198h, 8003b330h, 8002fd41h
	kinfo_entry 5101, 8003B298h, 8003B430h, 8002FDD7h
	kinfo_entry 5530, 8003C118h, 8003c2c4h, 8002ff55h
	kinfo_entry 5713, 8003C138h, 8003c2e4h, 8002ff6fh
	kinfo_entry 5838, 8003C138h, 8003c2e4h, 8002ff6fh
*/

bool getKernelPointers(uintptr_t* var_top_addr, uintptr_t* move_saved_data) {
  PXBOX_KRNL_VERSION version = (PXBOX_KRNL_VERSION)&XboxKrnlVersion;
  if (0) { /* Ugly piece of code.. blame rmenhal for the LUT*/ }
  else if (version->Build == 3944) { *var_top_addr = 0x8003bff0; *move_saved_data = 0x80031656; }
  else if (version->Build == 4034) { *var_top_addr = 0x8003c0b0; *move_saved_data = 0x80031293; }
  else if (version->Build == 4817) { *var_top_addr = 0x8003b330; *move_saved_data = 0x8002fd41; }
  else if (version->Build == 5101) { *var_top_addr = 0x8003b430; *move_saved_data = 0x8002fdd7; }
  else if (version->Build == 5530) { *var_top_addr = 0x8003c2c4; *move_saved_data = 0x8002ff55; }
  else if (version->Build == 5713) { *var_top_addr = 0x8003c2e4; *move_saved_data = 0x8002ff6f; } 
  else if (version->Build == 5838) { *var_top_addr = 0x8003c2e4; *move_saved_data = 0x8002ff6f; } 
  else {
    printf("Kernel unknown!\n");
    return false;
  } 
  return true;  
}

void* expand_kernel(void) {
/*
.top_addr		equ 0-4
.expansion_end_addr_ex	equ .top_addr-4
.local_var_size		equ -.expansion_end_addr_ex
*/
	
  uintptr_t KI_top_var_addr;
  uintptr_t moveSavedData;
  if (getKernelPointers(&KI_top_var_addr,&moveSavedData) == false) {
    printf("Aborting!\n");
    return NULL;
  }

 //FIXME: Will never happen?!
  if (KI_expansion_size == 0) {
    printf("Didn't ask for expansion!\n");
    return NULL;
  }

	uint32_t top_addr = *(uint32_t*)KI_top_var_addr; // End of kernel
	uint32_t expansion_end_addr_ex = top_addr + KI_expansion_size; // New end of kernel after expansion
	
  uintptr_t edi = (uintptr_t)AvGetSavedDataAddress(); // Check if we have GPU data
  if (edi != 0) {

	  uint32_t esi =	MmQueryAllocationSize((void*)edi);
	  uintptr_t eax = MmGetPhysicalAddress((void*)edi); // Get the location of saved data
    uintptr_t edx = eax+esi; // End of saved data

	  if (expansion_end_addr_ex <= eax) { goto expand; } // If it's above the new kernel: OK!
 	  if (edx <= top_addr) { goto expand; } // If it's below the new kernel: OK!
	
    // If it's coliding with the area we want to modify we have to allocate more space so we can move it
  
    edi = (uintptr_t)MmAllocateContiguousMemoryEx(esi,0,-1,0,0x404); // Reserve memory to move the data to
    if ((void*)edi == NULL) { goto error; }

	  eax = (uintptr_t)MmGetPhysicalAddress((void*)edi);

	  edx = eax+esi; // End of new saved data
	  if (expansion_end_addr_ex <= eax) { goto movedata; } // If it's above the new kernel: OK!
	  if (edx > top_addr) { goto error; } // If it's inside our new Kernel: FAIL!

  movedata:	

    printf("Fucked! KernelMoveSavedData\n");
//    return NULL;
    NTAPI VOID (*AvRelocateSavedDataAddress)(IN PVOID NewAddress, IN SIZE_T NumberOfBytes) = (void*)moveSavedData;
    AvRelocateSavedDataAddress((void*)edi,esi); // Move memory to new location

  }
  
expand:;
  uint32_t KI_expd_space = (uintptr_t)MmAllocateContiguousMemoryEx(KI_expansion_size,top_addr,expansion_end_addr_ex-1,0,4);
  if ((void*)KI_expd_space == NULL) { goto error; }

  /*FIXME: > * < this used to be here.. why? */ KI_top_var_addr = top_addr + KI_expansion_size;
		
  MmPersistContiguousMemory((void*)KI_expd_space,KI_expansion_size,TRUE);

  printf("New space allocated at 0x%08X\n",KI_expd_space);

  return (void*)KI_expd_space;

error:	
	printf("Something went wrong!\n");
  return NULL;
}


/*
No idea why this would have to be done :s
patchmskeyback:
	mov	eax,[XePublicKeyData]
	test	eax,eax
	jz	.fail

	mov	dword [eax+10h],10001h
	mov	dword [eax+110h],0A44B1BBDh
.fail:
	ret
*/



/*

  ;;; Expand code segment size too. This is required for kernels 5530 and above,
  ;;; because those kernels downsize code segment when they discard the INIT
  ;;; section. It doesn't do really anything for kernels 5101 or less.
  ;;;
  ;;; This will also make Phoenix Bios Loader 1.3 - 1.4.1 work with 5530 and 5713
  ;;; kernel boxes.

  This referes to the segment pointed at by the Kernel CS register

*/


void expand_code_segment(void) {
  __asm__ __volatile__("mov	fjmp,%%eax\n"

                       // Create space on stack for ljmp target
                       "push %%eax\n" // Should be cs
                       "push %%eax\n" // fjmp [lower 4 bytes]

                       // Create space on stack for gdt
                       "push %%eax\n" // 4,5,6,7: gdt base
                       "push %%eax\n" // 2,3: gdt limit [upper bytes]
  
                       // Get gdt
                       "sgdt 2(%%esp)\n" // Write to bytes 2,3:4,5,6,7 as limit:base
                       "pop	%%eax\n" // Discard limit

                       // Find gdt entry
                       "pop	%%eax\n" // eax = gdt base
                       "mov	%%cs,%%edx\n" // edx = cs
                       "and $0xFFFF,%%edx\n"
                       "add	%%edx,%%eax\n" // eax = base + cs

                       // Set gdt entry
                       "movw $0xFFFF,(%%eax)\n" // limit 0:15 = 0xFFFF
                       "orb	$0xF,6(%%eax)\n" // limit 16:19 = 0xB -> why not 0xF?

/*
                       "orb	$0x80,6(%%eax)\n" // Page granularity
                       "andb $0xFE,5(%%eax)\n" // Access = 0
*/

                       // Finalize ljmp target and jump
                       "mov %%edx,4(%%esp)\n" // Set up ljmp target (upper 4 bytes = base + cs)
                       "wbinvd\n" // Make sure nothing is sitting in cache
                       "ljmp *(%%esp)\n" // Do the far jmp << crashes.. always
        
                       // Landing zone with new CS
                       "fjmp:\n"    
                       "pop	%%eax\n" // Discard ljmp target   
                       "pop	%%eax" // ...
                       :
                       :
                       :"eax","edx","memory");
  return;
}
	
/*
;;; If we expanded the kernel, xboxkrnl.exe headers must be made consistent.
*/
void patchheaders(void) {

//	if (KI_expd_space == 0) { goto done; } // Make sure we actually allocated more space

  uintptr_t pe = 0x80010000;
  uintptr_t peHeader = pe + *(uint32_t*)(pe+0x3C);

  uint16_t numberOfSections = *(uint16_t*)(peHeader+0x6);
  uint16_t sizeOfOptionalHeader = *(uint16_t*)(peHeader+0x14);

  uintptr_t section = peHeader + 0x18 + sizeOfOptionalHeader + (numberOfSections-2)*0x28;

#if 1
  // This is probably some .text or .data section?!
  uint32_t* s0VirtualSize = (uint32_t*)(section+0x8);
  uint32_t* s0SizeOfRawData = (uint32_t*)(section+0x10);
	*s0VirtualSize += KI_expansion_size;			//; VirtualSize
	*s0SizeOfRawData += KI_expansion_size;			//; SizeOfRawData

  // Last section is always init in xbox kernel
  uint32_t* s1VirtualSize = (uint32_t*)(section+0x28+0x8);
  uint32_t* s1SizeOfRawData = (uint32_t*)(section+0x28+0x10);
  uint32_t* s1VirtualAddress = (uint32_t*)(section+0x28+0xC);
  uint32_t* s1PointerToRawData = (uint32_t*)(section+0x28+0x14);
  *s1VirtualSize -= KI_expansion_size;			// INIT section VirtualSize 
  *s1SizeOfRawData -= KI_expansion_size;		// INIT section SizeOfRawData
printf("New .init size is 0x%08X / 0x%08X\n",*s1VirtualSize,*s1SizeOfRawData);
  *s1VirtualAddress += KI_expansion_size;  // INIT section VirtualAddress
	*s1PointerToRawData += KI_expansion_size;// INIT section PointerToRawData
#endif

	return;
}

void* resizeKernel(void) {
  void* base = expand_kernel();

	KIRQL l = KeRaiseIrqlToDpcLevelFix();

	disableInterrupts();
  disableWriteProtect();

  flushTlb();
  flushCache();

//FIXME: Why does this keep crashing?!
#if 0
	expand_code_segment();
#endif

  /*
    FIXME: Why?! What happens to it in nkpatcher? Maybe expects to be signed with habibi?
  	patchmskeyback();
  */  

	patchheaders();

  /*
	  push	xa_feature_param
	  push	ebx
	  push	80010000h
	  call	dword [ebx + KI_patcher]
  */

  //TODO: Actual work happens here!

  flushTlb();
  flushCache();

  enableWriteProtect();
  enableInterrupts();

  KfLowerIrqlFix(l);

  return base; 
}
