#define STRING(var,text) \
const char* var; \
__asm__ __volatile__("call 1f\n" \
                     ".asciz \"" text "\"\n" \
                     "1:\n" \
                     "pop %%eax" \
                     :"=a"(var));

// Positive length = Print bytes normally
// Negative length = Print bytes in reverse order
char* hexString(char* s, const uint8_t* data, signed int length) { 
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

size_t stringLength(const char* s) {
	size_t l = 0;
  while(*s++) { l++; }
	return l;
}
