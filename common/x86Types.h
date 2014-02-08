typedef struct {
  unsigned short   link;
  uint16_t   link_h;

  unsigned long   esp0;
  unsigned short   ss0;
  unsigned short   ss0_h;

  unsigned long   esp1;
  unsigned short   ss1;
  unsigned short   ss1_h;

  unsigned long   esp2;
  unsigned short   ss2;
  unsigned short   ss2_h;

  unsigned long   cr3;
  unsigned long   eip;
  unsigned long   eflags;

  unsigned long   eax;
  unsigned long   ecx;
  unsigned long   edx;
  unsigned long    ebx;

  unsigned long   esp;
  unsigned long   ebp;

  unsigned long   esi;
  unsigned long   edi;

  unsigned short   es;
  unsigned short   es_h;

  unsigned short   cs;
  unsigned short   cs_h;

  unsigned short   ss;
  unsigned short   ss_h;

  unsigned short   ds;
  unsigned short   ds_h;

  unsigned short   fs;
  unsigned short   fs_h;

  unsigned short   gs;
  unsigned short   gs_h;

  unsigned short   ldt;
  unsigned short   ldt_h;

  unsigned short   trap;
  uint16_t iomap;  
} __attribute__((packed)) Tss_t;

typedef struct {
  uint16_t limit0FFFF; //0
  union {
    struct {
      uint32_t base00FFFFFF:24; //16
      uint32_t type:4; //40
      uint32_t descriptor:1; //44
      uint32_t privilege:2; //46
      uint32_t present:1; //47
    } __attribute__((packed));
    struct {
      uint32_t pad1:24; //16
      uint32_t accessed:1; //40
      uint32_t busy:1; //41
      uint32_t pad2:6; //42
    } __attribute__((packed));
  } __attribute__((packed));
  uint8_t limitF0000:4; //48
  uint8_t os:1; //52
  uint8_t zero:1; //53
  uint8_t size:1; //54
  uint8_t granularity:1; //55
  uint8_t baseFF000000; //56
} __attribute__((packed)) GdtDescriptor_t;

