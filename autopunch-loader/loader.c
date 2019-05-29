#include "loader.h"

BOOL cEnumWindowCallbackList(HWND handle, LPARAM data) {
	void enumWindowCallbackList(void *handle, void *data);
    enumWindowCallbackList((void*)handle, (void*)data);
    return TRUE;
}

BOOL cEnumWindowCallbackSetName(HWND handle, LPARAM data) {
	void enumWindowCallbackSetName(void *handle, void *data);
    enumWindowCallbackSetName((void*)handle, (void*)data);
    return TRUE;
}
