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
