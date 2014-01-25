
uint16_t getVendorID(uint8_t bus, uint8_t device, uint8_t function) {
  uint16_t buffer;
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),0x0,&buffer,2,0);
  return buffer;
}


void bar(uint8_t bus, uint8_t device, uint8_t function, unsigned int offset) {
  uint32_t bar;
  uint32_t one = -1;
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),offset,&bar,4,0);
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),offset,&one,4,1);
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),offset,&one,4,0);
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),offset,&bar,4,1);
  uint32_t length = ~one + 1;
  if (bar&1) {
    uint16_t base = bar & 0xFFF0;
    printf("PCI: i/o: 0x%04X - 0x%04X\n",base,base+length);
  } else {
    uint32_t base = bar & 0xFFFFFFF0;
    printf("PCI: memory:  0x%08X - 0x%08X\n",base,base+length);
  }
  return;
}

void checkFunction(uint8_t bus, uint8_t device, uint8_t function) {
  uint16_t vendor;
  uint8_t type;
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),0x0,&vendor,2,0);
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),0xE,&type,1,0);
  printf("PCI: (bus: %i dev: %i fun: %i) vendor 0x%04X (type: %i)\n",bus,device,function,vendor,type);
  if ((type & 0x7F) == 0) {
    bar(bus,device,function,0x10);
    bar(bus,device,function,0x14);
  } else if ((type & 0x7F) == 1) {
    bar(bus,device,function,0x10);
    bar(bus,device,function,0x14);
    bar(bus,device,function,0x18);
    bar(bus,device,function,0x1C);
    bar(bus,device,function,0x20);
    bar(bus,device,function,0x24);
  } else {
    printf("Unhandled type: %i\n",type&0x7F);
  }
}

void checkDevice(uint8_t bus, uint8_t device) {
  uint8_t function = 0;

  uint16_t vendorID = getVendorID(bus, device, function);
  if(vendorID == 0xFFFF) {
    return;
  }
printf("Dev found %i %i %i\n",bus,device,function);

  checkFunction(bus, device, function);
return;
//  headerType = getHeaderType(bus, device, function);
  uint8_t type;
  HalReadWritePCISpace(bus,PCI_SLOT(device,function),0xE,&type,1,0);
  if(type & 0x80) {
    /* It is a multi-function device, so check remaining functions */
    for(function = 1; function < 8; function++) {
      if(getVendorID(bus, device, function) != 0xFFFF) {
        checkFunction(bus, device, function);
      }
    }
  }
}


void pcidump(void) {
  int bus;
  uint8_t device;


  uint16_t buffer;
  HalReadWritePCISpace(0,PCI_SLOT(30,0),0x2,&buffer,2,0);
  printf("AGPBridge: 0x%04X 0x%04X\n",getVendorID(0,30,0),buffer);

  for(bus = 0; bus < 3; bus++) {
    printf("PCI: Checking bus %i\n",bus);
    for(device = 0; device < 32; device++) {
      checkDevice(bus, device);
    }
  }
}
