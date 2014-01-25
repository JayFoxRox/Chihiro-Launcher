void launch(const char* path, uint32_t type, void* data) {

  if (LaunchDataPage == NULL) {
    LaunchDataPage = MmAllocateContiguousMemory(0x1000);
  }

  if (LaunchDataPage == NULL) {
    return; 
  }

  MmPersistContiguousMemory(LaunchDataPage, 0x1000, TRUE);

	memset((void*)LaunchDataPage, 0, 0x1000);
	
	LaunchDataPage->Header.dwLaunchDataType = type;
	LaunchDataPage->Header.dwTitleId = 0;
	
	strcpy(LaunchDataPage->Header.szLaunchPath,path);

  if (type != 0xFFFFFFFF) {
    memcpy(LaunchDataPage->LaunchData,data,3072);
  }

	char *lastSlash = strrchr(LaunchDataPage->Header.szLaunchPath, '\\');
	if (lastSlash != NULL) {
		*lastSlash = ';';
		HalReturnToFirmware(ReturnFirmwareQuickReboot);
	}

  return;

}
