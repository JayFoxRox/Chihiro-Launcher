void unmount(const char* device) {
	ANSI_STRING aDevice;
	RtlInitAnsiString(&aDevice, device); 
  int ret = IoDeleteSymbolicLink(&aDevice);
  printf("%X: Unmounting '%s'\n",ret,device);
  return;
}

/*
void deleteDevice(const char* device) {
	ANSI_STRING aDevice;
	RtlInitAnsiString(&aDevice, device); 
  int ret = IoDeleteDevice(&aDevice);
  printf("%X: Deleting '%s'\n",ret,device);
  return;
}
*/
 
 /*
// Mount the D: drive to a given device and directory
// Device = "\\??\\D:"
// szDevice = "Cdrom0" or "Harddisk0\Partition6"
// szDir = "" or "Game1"
void mountOld(const char* device, char* szDevice, char* szDir) {
      char szSourceDevice[256];
      char szDestinationDrive[16];
 
      strcpy(szDestinationDrive,device);
      sprintf(szSourceDevice,"\\Device\\%s",szDevice);
 
      if (*szDir != 0x00 && *szDir != '\\')
      {
            strcat(szSourceDevice, "\\");
            strcat(szSourceDevice, szDir);
      }
 
      stUNICODE_STRING LinkName =
      {
            strlen(szDestinationDrive),
            strlen(szDestinationDrive) + 1,
            (wchar_t *)szDestinationDrive
      };
     
      stUNICODE_STRING DeviceName =
      {
            strlen(szSourceDevice),
            strlen(szSourceDevice) + 1,
            (wchar_t *)szSourceDevice
      };
 
      IoCreateSymbolicLink(&LinkName, &DeviceName);
}// End xMountD(..)
*/


void mount(const char* device, const char* target) {
 	ANSI_STRING aDevice, aTarget;
	RtlInitAnsiString(&aDevice, device); 
 	RtlInitAnsiString(&aTarget, target); 
  int ret = IoCreateSymbolicLink(&aDevice, &aTarget);
  printf("%X: Mounting '%s' to '%s'\n",ret,device,target);
  return;
}
 
 
