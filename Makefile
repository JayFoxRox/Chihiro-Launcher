#
# update this variable to wherever you installed the OpenXDK libraries
#
PREFIX=.

CC = i686-w64-mingw32-gcc
CXBE = bin/cxbe
#SDLFLAGS = -DENABLE_XBOX -DDISABLE_CDROM 

CC_FLAGS = -m32 -march=i386 -O0 -g -shared -std=gnu99 -ffreestanding -nostdlib -fno-builtin -fno-exceptions # $(SDLFLAGS)
INCLUDE  = -I$(PREFIX)/i386-pc-xbox/include -I$(PREFIX)/include #-I$(PREFIX)/include/SDL

CLINK = -nostdlib -m32 -march=i386 -O0 -g 
ALIGN = -Wl,--file-alignment,0x20 -Wl,--section-alignment,0x20 
SHARED = -shared
ENTRYPOINT = -Wl,--entry,_WinMainCRTStartup 
STRIP = # -Wl,--strip-all 
LD_FLAGS = -m32 -march=i386 -O0 $(CLINK) $(ALIGN) $(SHARED) $(ENTRYPOINT) $(STRIP)
LD_DIRS = -L$(PREFIX)/i386-pc-xbox/lib -L$(PREFIX)/lib 
LD_LIBS  = $(LD_DIRS) -lopenxdk -lhal -lusb -lc -lhal -lc -lxboxkrnl #-lSDL 

all: default.xbe

transfer: default.xbe
	wput -u ftp://xbox:xbox@192.168.177.80:21/E/Games/Chihiro/default.xbe default.xbe

log:
	@echo "---"
	@wget -q -O - ftp://xbox:xbox@192.168.177.80:21/E/chihiro/log.txt
	@echo "---"

crash:
	@echo "---"
	@wget -q -O - ftp://xbox:xbox@192.168.177.80:21/E/chihiro/crash.txt
	@echo "---"

.c.o:
	$(CC) -c $< $(CC_FLAGS) $(INCLUDE)

default.exe: main.o 
	$(CC) -o $@ $< $(LD_LIBS) $(LD_FLAGS)

default.xbe: default.exe
	$(CXBE) -MODE:DEBUG -TITLE:"Chihiro-Launcher" -DUMPINFO:"cxbe.txt" -OUT:"$@" $< > /dev/null

clean: 
	rm -f *.o *.exe *.dll *.xbe *.cxbe cxbe.txt
