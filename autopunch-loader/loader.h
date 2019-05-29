#ifndef LOADER_H
#define LOADER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

BOOL cEnumWindowCallbackList(HWND handle, LPARAM data);
BOOL cEnumWindowCallbackSetName(HWND handle, LPARAM data);

#endif //LOADER_H
