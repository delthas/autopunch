#include <windows.h>

int main(int argc, char **argv) {
	if(argc != 3) {
		return 0;
	}
	HMODULE module = LoadLibraryA(argv[1]);
	if(!module) {
		return 0;
	}
	FARPROC proc = GetProcAddress(module, argv[2]);
	return (int)proc;
}
