void isIoOperation(uint8_t* code) {
  
}

void searchIoOperations(void* current,void* base) {

  
  if (call) {
  }

  while(1) {

    if (isIoOperation) {
    } 
    if (jump) {
      // If the target is before the entry point
      if (target < base) {
        if (searchIoOperations(target,target)) {
          return true;
        }
      }
      // If the target is still in front of us
      if (target > current) {
        if (searchIoOperations(target,current)) {
          return true;
        }
      }
    }
    if (ret) {
      return false;
    }

    instruction = instruction->next;

  }
}

