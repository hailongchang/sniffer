EXE=sniffer.exe
TARGET_PATH=.
VERBOSE_PATH=verbose
CFLAGS= /nologo /c /EHsc /Od /Oi /I"C:\ProgrammingWardrobe\WpdPack\Include" /DWIN32
LIBPATH= /LIBPATH:"C:\ProgrammingWardrobe\WpdPack\Lib"
LINKFLAGS = /out:"$(TARGET_PATH)/$(EXE)" /nologo 

All :	$EXE
$EXE:	$(VERBOSE_PATH) sniffer.obj GetOpt.obj
	link $(LINKFLAGS) $(LIBPATH) "$(VERBOSE_PATH)/sniffer.obj" "$(VERBOSE_PATH)/GetOpt.obj" wpcap.lib ws2_32.lib
$(VERBOSE_PATH):
	if not exist $(VERBOSE_PATH) mkdir $(VERBOSE_PATH)
sniffer.obj:	sniffer.cpp
	cl $(CFLAGS) sniffer.cpp /Fo"$(VERBOSE_PATH)/sniffer.obj"
GetOpt.obj:	 GetOpt.cpp
	cl $(CFLAGS) GetOpt.cpp /Fo"$(VERBOSE_PATH)/GetOpt.obj"
clean:
	cd $(VERBOSE_PATH)
		if exist *.obj del *.obj

	cd "../$(TARGET_PATH)"
		if exist $(EXE) del $(EXE)

