//FIXME: Static (inline?), macro or .c file

// Code generator

void* encodePush(void* address, uint32_t value) {
  uint8_t* code = address;
  code[0] = 0x68;
  *(uint32_t*)&code[1] = value;
  return &code[5];
}

void* encodeJmp(void* address, uintptr_t target) {
  uint8_t* code = address;
  code[0] = 0xE9;
  *(uint32_t*)&code[1] = (uintptr_t)target-(uintptr_t)address-5;
  return &code[5];
}

void* encodeCall(void* address, uintptr_t target) {
  uint8_t* code = address;
  code[0] = 0xE8;
  *(uint32_t*)&code[1] = (uintptr_t)target-(uintptr_t)address-5;
  return &code[5];
}

void* encodePushEax(void* address) {
  uint8_t* code = address;
  code[0] = 0x50;
  return &code[1];
}

void* encodePopEax(void* address) {
  uint8_t* code = address;
  code[0] = 0x58;
  return &code[1];
}

void* encodeRet(void* address) {
  uint8_t* code = address;
  code[0] = 0xC3;
  return &code[1];
}

void* encodeInt3(void* address) {
  uint8_t* code = address;
  code[0] = 0xCC;
  return &code[1];
}
