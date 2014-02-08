uint64_t rdmsr(uint32_t msr, uint32_t* pHigh, uint32_t* pLow) {
  uint32_t low, high; 

  __asm__ __volatile__ ("rdmsr"
                        :"=a"(low), "=d"(high)
                        :"c"(msr));

  uint64_t value = ((uint64_t)high << 32) | (uint64_t)low;
  if (pLow) { *pLow = low; }
  if (pHigh) { *pHigh = high; }
  return value;
}
 
void wrmsr(uint32_t msr, uint32_t high, uint32_t low) {
  __asm__ __volatile__ ("wrmsr"
                        :
                        :"c"(msr),"a"(low),"d"(high));
  return;
}

void disableInterrupts(void) {
  __asm__ __volatile__("cli");
  return;
}

void enableInterrupts(void) {
  __asm__ __volatile__("sti");
  return;
}

void disableCache(void) {
  uint32_t mask = (1 << 30) | (1 << 29); // CD | NW
  __asm__ __volatile__ ("movl %%cr0,%%eax\n"
                        "orl %%ecx,%%eax\n"
                        "movl %%eax,%%cr0"
                        :
                        :"c"(mask)
                        :"eax","memory");
  return;
}

void enableCache(void) {
  uint32_t mask = ~((1 << 30) | (1 << 29)); // CD | NW
  __asm__ __volatile__ ("movl %%cr0,%%eax\n"
                        "andl %%ecx,%%eax\n"
                        "movl %%eax,%%cr0"
                        :
                        :"c"(mask)
                        :"eax","memory");
  return;
}

void disableWriteProtect(void) {
  uint32_t mask = ~(1 << 16); // WP
  __asm__ __volatile__ ("movl %%cr0,%%eax\n"
                        "andl %%ecx,%%eax\n"
                        "movl %%eax,%%cr0"
                        :
                        :"c"(mask)
                        :"eax","memory");
  return;
}

void enableWriteProtect(void) {
  uint32_t mask = (1 << 16); // WP
  __asm__ __volatile__ ("movl %%cr0,%%eax\n"
                        "orl %%ecx,%%eax\n"
                        "movl %%eax,%%cr0"
                        :
                        :"c"(mask)
                        :"eax","memory");
  return;
}

void flushCache(void) {
  __asm__ __volatile__("wbinvd");
  return;
}

void flushTlb(void) {
  __asm__ __volatile__("movl %%cr3, %%eax\n"
                       "movl %%eax, %%cr3"
                       :
                       :
                       :"eax","memory");
  return;
}

void breakpoint(void) {
  __asm__ __volatile__("int3");
  return;
}

uint16_t getCs(void) {
  uint16_t cs;
  __asm__ __volatile__ ("mov %%cs,%%ax"
                       :"=a"(cs));
  return cs;
}

uint16_t getDs(void) {
  uint16_t ds;
  __asm__ __volatile__ ("mov %%ds,%%ax"
                       :"=a"(ds));
  return ds;
}

uint16_t getSs(void) {
  uint16_t ss;
  __asm__ __volatile__ ("mov %%ss,%%ax"
                       :"=a"(ss));
  return ss;
}

uint16_t getTr(void) {
  uint16_t tr;
  __asm__ __volatile__ ("str %%eax"
                        :"=a"(tr));
  return tr;
}

void getGdt(uint16_t* pLimit, uintptr_t* pBase) {
  uint32_t low, high; 

  __asm__ __volatile__ ("sub $8,%%esp\n"
                        "sgdt 2(%%esp)\n"
                        "pop %%eax\n"
                        "pop %%edx"
                        :"=a"(low), "=d"(high));

  if (pBase) { *pBase = high; }
  if (pLimit) { *pLimit = low >> 16; }

  return;
}

void setGdt(uint16_t limit, uintptr_t base) {
  __asm__ __volatile__ ("push %%edx\n"
                        "push %%eax\n"
                        "lgdt 2(%%esp)\n"
                        "add $8,%%esp"
                        :
                        :"a"(limit << 16), "d"(base));
  return;
}

void setTr(uint16_t tr) {
  __asm__ __volatile__ ("ltr %%ax"    
                        :
                        :"a"(tr));
  return;
}

void setCs(uint16_t cs) {
  __asm__ __volatile__ ("push %%ax\n"
                        "call ret1\n"
                        "ret1:\n"
                        "addl $(ret2 - ret1), (%%esp)\n"
                        "retl\n"
                        "ret2:"
                        :
                        :"a"(cs));
  return;
}

void lcall(uint16_t segment, uint32_t offset) {
  uint32_t destination[] = {
    offset,
    segment
  };
 __asm__ __volatile__("lcall *(%%eax)"
											:
											:"a"(destination));
  return;
}

void ret(void);
__asm__("_ret: ret\n");

void iret(void);
__asm__("_iret: iret\nret");

void iretLoop(void);
__asm__("_iretLoop: iret\njmp _iretLoop");

uintptr_t getEip(void);
__asm__("_getEip: pop %eax\nret");
