// +build windows
//go:generate rsrc -arch=amd64 -manifest loader.manifest -o rsrc_amd64.syso
//go:generate rsrc -arch=386 -manifest loader.manifest -o rsrc_386.syso
//go:generate autopunch-packer autopunch.x86.dbg.dll dll86Dbg.go dllData86Dbg
//go:generate autopunch-packer autopunch.x64.dbg.dll dll64Dbg_amd64.go dllData64Dbg
//go:generate autopunch-packer autopunch.x86.rel.dll dll86Rel.go dllData86Rel
//go:generate autopunch-packer autopunch.x64.rel.dll dll64Rel_amd64.go dllData64Rel
//go:generate autopunch-packer ..\autopunch-address\address.exe address.go addressData

package main

/*
#include "loader.h"
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/akutz/sortfold"
	"golang.org/x/sys/windows"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/machinebox/progress"
)

const (
	DllName64Dbg = "autopunch.x64.dbg.dll"
	DllName86Dbg = "autopunch.x86.dbg.dll"
	DllName64Rel = "autopunch.x64.rel.dll"
	DllName86Rel = "autopunch.x86.rel.dll"
)

var processExcludes = []string{"explorer.exe", "firefox.exe", "cmd.exe", "mintty.exe"}
var processPreferreds = []string{"th123.exe"}

const PROCESSOR_ARCHITECTURE_AMD64 = 9

type systeminfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

var (
	dllKernel                     = windows.NewLazyDLL("kernel32.dll")
	dllUser                       = windows.NewLazyDLL("user32.dll")
	dllVersions                   = windows.NewLazyDLL("version.dll")
	dllPsApi                      = windows.NewLazyDLL("psapi.dll")
	procQueryFullProcessImageName = dllKernel.NewProc("QueryFullProcessImageNameW")
	procVirtualAllocEx            = dllKernel.NewProc("VirtualAllocEx")
	procVirtualFreeEx             = dllKernel.NewProc("VirtualFreeEx")
	procWriteProcessMemory        = dllKernel.NewProc("WriteProcessMemory")
	procCreateRemoteThread        = dllKernel.NewProc("CreateRemoteThread")
	procGetExitCodeThread         = dllKernel.NewProc("GetExitCodeThread")
	procGetNativeSystemInfo       = dllKernel.NewProc("GetNativeSystemInfo")
	procEnumProcessModulesEx      = dllPsApi.NewProc("EnumProcessModulesEx")
	procGetModuleFileNameEx       = dllPsApi.NewProc("GetModuleFileNameExW")
	procVerQueryValue             = dllVersions.NewProc("VerQueryValueW")
	procGetFileVersionInfoSize    = dllVersions.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo        = dllVersions.NewProc("GetFileVersionInfoW")
	procGetWindowThreadProcessId  = dllUser.NewProc("GetWindowThreadProcessId")
	procGetWindowTextLength       = dllUser.NewProc("GetWindowTextLengthW")
	procGetWindowText             = dllUser.NewProc("GetWindowTextW")
	procSetWindowText             = dllUser.NewProc("SetWindowTextW")
	procIsWindowVisible           = dllUser.NewProc("IsWindowVisible")
	procEnumWindows               = dllUser.NewProc("EnumWindows")
)

type processModel struct {
	walk.ListModelBase
	items []processItem
}

func (m *processModel) ItemCount() int {
	return len(m.items)
}

func (m *processModel) Value(index int) interface{} {
	return m.items[index].name
}

type processItem struct {
	name      string
	preferred bool
	path      string
	pid       uint32
}

type processItems []processItem

func (p processItems) Len() int {
	return len(p)
}

func (p processItems) Less(i, j int) bool {
	if p[i].preferred && !p[j].preferred {
		return true
	}
	if !p[i].preferred && p[j].preferred {
		return false
	}
	return sortfold.CompareFold(p[i].name, p[j].name) <= 0
}

func (p processItems) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

type module struct {
	name        string
	description string
	win         map[uint32][]string // processId -> windows texts
}

var logErr = log.New(os.Stderr, "err: ", log.Lshortfile|log.Ldate|log.Ltime)

//export enumWindowCallbackList
func enumWindowCallbackList(handle unsafe.Pointer, data unsafe.Pointer) {
	r, _, _ := procIsWindowVisible.Call(uintptr(handle))
	if r == 0 {
		return
	}
	r, _, err := procGetWindowTextLength.Call(uintptr(handle))
	if r == 0 {
		if err != windows.ERROR_SUCCESS {
			logErr.Printf("GetWindowTextLength returned: %v", err)
			return
		}
		return
	}
	l := int(r)
	textUtf16 := make([]uint16, l+1)
	r, _, err = procGetWindowText.Call(uintptr(handle), uintptr(unsafe.Pointer(&textUtf16[0])), uintptr(l+1))
	if r == 0 {
		if err != windows.ERROR_SUCCESS {
			logErr.Printf("GetWindowText returned: %v", err)
			return
		}
		return
	}
	textUtf16 = textUtf16[:l]
	for i, c := range textUtf16 {
		if c == 0 {
			logErr.Printf("truncating NUL in window text string %v\n", string(utf16.Decode(textUtf16)))
			textUtf16 = textUtf16[:i]
			break
		}
	}
	text := string(utf16.Decode(textUtf16))

	var processId uint32
	r, _, err = procGetWindowThreadProcessId.Call(uintptr(handle), uintptr(unsafe.Pointer(&processId)))
	if r == 0 {
		logErr.Printf("GetWindowThreadProcessId returned: %v", err)
	}
	wins := *(*map[uint32][]string)(unsafe.Pointer(data))
	wins[processId] = append(wins[processId], text)
}

func refresh(model *processModel, lb *walk.ListBox) error {
	defer func() {
		if r := recover(); r != nil {
			dialog("Process listing failed", "Process listing failed! This should not happen.\nError: "+r.(error).Error(), walk.MsgBoxIconError)
			mw.Close()
		}
	}()

	modules := make(map[string]module) // process path ->
	wins := make(map[uint32][]string)  // processId -> windows texts

	r, _, err := procEnumWindows.Call(uintptr(C.cEnumWindowCallbackList), uintptr(unsafe.Pointer(&wins)))
	if r == 0 {
		return fmt.Errorf("could not enumerate windows: EnumWindows returned: %v", err)
	}

	handleSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("could not enumerate processes: CreateToolhelp32Snapshot returned: %v", err)
	}
	entry := windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}
	err = windows.Process32First(handleSnapshot, &entry)
	if err != nil {
		return fmt.Errorf("could not enumerate processes: Process32First returned: %v", err)
	}
outer:
	for windows.Process32Next(handleSnapshot, &entry) == nil {
		win, ok := wins[entry.ProcessID]
		if !ok {
			continue
		}

		exeNameLen := len(entry.ExeFile)
		for i, c := range entry.ExeFile {
			if c == 0 {
				exeNameLen = i
				break
			}
		}
		exeName := string(utf16.Decode(entry.ExeFile[:exeNameLen]))

		for _, processExclude := range processExcludes {
			if strings.EqualFold(processExclude, exeName) {
				continue outer
			}
		}

		handleProcess, err := windows.OpenProcess(0x1FFFFF /* PROCESS_ALL_ACCESS */, false, entry.ProcessID)
		if err != nil { // fails if run as administrator
			continue
		}
		exePathUtf16 := make([]uint16, windows.MAX_PATH)
		var exePathLen = uint32(len(exePathUtf16))
		r, _, err = procQueryFullProcessImageName.Call(uintptr(handleProcess), 0, uintptr(unsafe.Pointer(&exePathUtf16[0])), uintptr(unsafe.Pointer(&exePathLen)))
		windows.CloseHandle(handleProcess)
		if r == 0 {
			logErr.Printf("QueryFullProcessImageName returned: %v", err)
			continue
		}
		exePathUtf16 = exePathUtf16[:exePathLen]
		for i, c := range exePathUtf16 {
			if c == 0 {
				logErr.Printf("truncating NUL in process image name string %v\n", string(utf16.Decode(exePathUtf16)))
				exePathUtf16 = exePathUtf16[:i]
				break
			}
		}
		exePath := string(utf16.Decode(exePathUtf16[:exePathLen]))

		m, ok := modules[exePath]
		if !ok {
			m = module{
				name: exeName,
				win:  make(map[uint32][]string),
			}

			var handle uint32
			r, _, err := procGetFileVersionInfoSize.Call(uintptr(unsafe.Pointer(&exePathUtf16[0])), uintptr(unsafe.Pointer(&handle)))
			if r != 0 {
				l := int(r)
				versionData := make([]byte, l)
				r, _, err = procGetFileVersionInfo.Call(uintptr(unsafe.Pointer(&exePathUtf16[0])), uintptr(unsafe.Pointer(&handle)), uintptr(l), uintptr(unsafe.Pointer(&versionData[0])))
				if r == 0 {
					logErr.Printf("GetFileVersionInfo returned for %s: %v", exeName, err)
					continue
				}
				var lang *struct {
					language uint16
					codepage uint16
				}
				subBlock := utf16.Encode([]rune("\\VarFileInfo\\Translation" + "\x00"))
				var blockLen uint32
				r, _, err = procVerQueryValue.Call(uintptr(unsafe.Pointer(&versionData[0])), uintptr(unsafe.Pointer(&subBlock[0])), uintptr(unsafe.Pointer(&lang)), uintptr(unsafe.Pointer(&blockLen)))
				if r != 0 && blockLen > 0 {
					subBlock = utf16.Encode([]rune(fmt.Sprintf("\\StringFileInfo\\%04x%04x\\FileDescription"+"\x00", lang.language, lang.codepage)))
					var descriptionUtf16 *uint16
					r, _, err = procVerQueryValue.Call(uintptr(unsafe.Pointer(&versionData[0])), uintptr(unsafe.Pointer(&subBlock[0])), uintptr(unsafe.Pointer(&descriptionUtf16)), uintptr(unsafe.Pointer(&blockLen)))
					if r != 0 && blockLen > 1 {
						descriptionUtf16Arr := *(*[]uint16)(unsafe.Pointer(&reflect.SliceHeader{
							Data: uintptr(unsafe.Pointer(descriptionUtf16)),
							Len:  int(blockLen - 1),
							Cap:  int(blockLen - 1),
						}))
						for i, c := range descriptionUtf16Arr {
							if c == 0 {
								fmt.Printf("truncating NUL in exe name string for %s in %v\n", exeName, string(utf16.Decode(descriptionUtf16Arr)))
								descriptionUtf16Arr = descriptionUtf16Arr[:i]
								break
							}
						}
						description := string(utf16.Decode(descriptionUtf16Arr))
						m.description = description
					}
				}
				runtime.KeepAlive(&versionData)
			}
			if m.description == "" {
				m.description = exeName
			}
			modules[exePath] = m
		}
		for _, v := range win {
			m.win[entry.ProcessID] = append(m.win[entry.ProcessID], v)
		}
	}

	items := make([]processItem, 0, 16)
	for path, m := range modules {
		for pid, wins := range m.win {
			for _, win := range wins {
				preferred := false
				for _, processPreferred := range processPreferreds {
					if strings.EqualFold(processPreferred, m.name) {
						preferred = true
						break
					}
				}
				items = append(items, processItem{
					name:      m.description + " - " + win,
					path:      path,
					pid:       pid,
					preferred: preferred,
				})
			}
		}
	}
	sort.Sort(processItems(items))
	model.items = items
	mw.Synchronize(func() {
		model.PublishItemsReset()
		if len(items) > 0 {
			lb.SetCurrentIndex(0)
		}
	})
	return nil
}

func inject(pid uint32, debug bool) {
	err, pretty := doInject(pid, debug)
	if err == nil {
		mw.Close()
		return
	}
	dialog("Injection failed!", pretty+"\n"+err.Error(), walk.MsgBoxIconError)
}

//export enumWindowCallbackSetName
func enumWindowCallbackSetName(handle unsafe.Pointer, data unsafe.Pointer) {
	pid := *(*uint32)(data)
	var windowPid uint32
	r, _, _ := procGetWindowThreadProcessId.Call(uintptr(handle), uintptr(unsafe.Pointer(&windowPid)))
	if r == 0 {
		return
	}
	if windowPid != pid {
		return
	}
	r, _, _ = procIsWindowVisible.Call(uintptr(handle))
	if r == 0 {
		return
	}
	r, _, _ = procGetWindowTextLength.Call(uintptr(handle))
	if r == 0 {
		return
	}
	l := int(r)
	textUtf16 := make([]uint16, l+1)
	r, _, _ = procGetWindowText.Call(uintptr(handle), uintptr(unsafe.Pointer(&textUtf16[0])), uintptr(l+1))
	if r == 0 {
		return
	}

	text := string(utf16.Decode(textUtf16[:l])) + " + autopunch " + version + "\x00"
	textUtf16 = utf16.Encode([]rune(text))
	_, _, _ = procSetWindowText.Call(uintptr(handle), uintptr(unsafe.Pointer(&textUtf16[0])))
}

func doInject(pid uint32, debug bool) (error, string) {
	handleProcess, err := windows.OpenProcess(0x1FFFFF /* PROCESS_ALL_ACCESS */, false, pid)
	if err != nil {
		return err, "Failed opening process!"
	}
	defer windows.CloseHandle(handleProcess)

	var compile64 bool
	var process64 bool
	if runtime.GOARCH == "amd64" {
		compile64 = true
		var wow64 bool
		err = windows.IsWow64Process(handleProcess, &wow64)
		if err != nil {
			return err, "Failed getting process bitness!"
		}
		process64 = !wow64
	} else {
		compile64 = false
		var systeminfo systeminfo
		_, _, _ = procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&systeminfo)))
		runtime64 := systeminfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
		if !runtime64 {
			process64 = false
		} else {
			var wow64 bool
			err = windows.IsWow64Process(handleProcess, &wow64)
			if err != nil {
				return err, "Failed getting process bitness!"
			}
			process64 = !wow64
		}
	}
	if process64 && !compile64 {
		return errors.New("this process is 64-bits and your autopunch version is 32-bits; please download autopunch 64-bits"), "Failed injecting process: wrong bitness!"
	}

	modules := make([]uintptr, 1024)
	var modulesCount uint32
	r, _, err := procEnumProcessModulesEx.Call(uintptr(handleProcess), uintptr(unsafe.Pointer(&modules[0])), uintptr(len(modules))*4, uintptr(unsafe.Pointer(&modulesCount)), 0x03 /* LIST_MODULES_ALL */)
	if r == 0 {
		return err, "Failed enumerating process modules!"
	}
	modules = modules[:modulesCount/4]
	for _, module := range modules {
		moduleUtf16 := make([]uint16, windows.MAX_PATH)
		r, _, err = procGetModuleFileNameEx.Call(uintptr(handleProcess), module, uintptr(unsafe.Pointer(&moduleUtf16[0])), uintptr(len(moduleUtf16)))
		if r == 0 {
			return err, "Failed getting process module name!"
		}
		for i, c := range moduleUtf16 {
			if c == 0 {
				moduleUtf16 = moduleUtf16[:i]
				break
			}
		}
		moduleName := string(utf16.Decode(moduleUtf16))
		fileName := filepath.Base(moduleName)
		if strings.Contains(fileName, "autopunch") {
			return nil, ""
		}
	}

	var loadLibraryAddr uintptr
	var dllPath string
	if !process64 {
		if compile64 {
			f, err := ioutil.TempFile("", "address-*.exe")
			if err != nil {
				return err, "Failed opening temporary address process file!"
			}
			_, err = f.Write(addressData)
			if err != nil {
				return err, "Failed writing to temporary address process file!"
			}
			f.Close()
			addressPath := f.Name()

			cmd := exec.Command(addressPath, "kernel32.dll", "LoadLibraryW")
			err = cmd.Start()
			if err != nil {
				return err, "Failed starting address process!"
			}
			err = cmd.Wait()
			if exitErr, ok := err.(*exec.ExitError); !ok {
				return err, "Failed running address process!"
			} else {
				code := exitErr.ExitCode()
				if code == -1 {
					return errors.New("address process failed to start (exit code -1)"), "Failed starting address process!"
				}
				if code == 0 {
					return errors.New("address process failed finding address (exit code 0)"), "Failed finding library address!"
				}
				loadLibraryAddr = uintptr(code)
			}
		} else {
			loadLibraryAddr = dllKernel.NewProc("LoadLibraryW").Addr()
		}

		if os.Getenv("AUTOPUNCH_DLL_FILE") == "1" {
			var dllName string
			if debug {
				dllName = DllName86Dbg
			} else {
				dllName = DllName86Rel
			}
			var err error
			dllPath, err = filepath.Abs(dllName)
			if err != nil {
				return err, "Failed finding path to local inject (x86) library!"
			}
		} else {
			f, err := ioutil.TempFile("", "autopunch.*.dll")
			if err != nil {
				return err, "Failed opening temporary inject (x86) library file!"
			}
			var dllData []byte
			if debug {
				dllData = dllData86Dbg
			} else {
				dllData = dllData86Rel
			}
			_, err = f.Write(dllData)
			if err != nil {
				return err, "Failed writing to temporary inject (x86) library file!"
			}
			f.Close()
			dllPath = f.Name()
		}
	} else {
		loadLibraryAddr = dllKernel.NewProc("LoadLibraryW").Addr()

		if os.Getenv("AUTOPUNCH_DLL_FILE") == "1" {
			var dllName string
			if debug {
				dllName = DllName64Dbg
			} else {
				dllName = DllName64Rel
			}
			var err error
			dllPath, err = filepath.Abs(dllName)
			if err != nil {
				return err, "Failed finding path to local inject (x64) library!"
			}
		} else {
			f, err := ioutil.TempFile("", "autopunch.*.dll")
			if err != nil {
				return err, "Failed opening temporary inject (x64) library file!"
			}
			var dllData []byte
			if debug {
				dllData = dllData64Dbg
			} else {
				dllData = dllData64Rel
			}
			_, err = f.Write(dllData)
			if err != nil {
				return err, "Failed writing to temporary inject (x64) library file!"
			}
			f.Close()
			dllPath = f.Name()
		}
	}

	if _, err := os.Stat(dllPath); err != nil {
		return err, "Failed finding temporary inject library file!"
	}
	dllPathC := utf16.Encode([]rune(dllPath + "\x00"))

	dllAddr, _, err := procVirtualAllocEx.Call(uintptr(handleProcess), 0, uintptr(len(dllPathC)*2), windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if dllAddr == 0 {
		return err, "Failed allocating memory in process!"
	}
	defer procVirtualFreeEx.Call(uintptr(handleProcess), dllAddr, 0, windows.MEM_RELEASE)
	r, _, err = procWriteProcessMemory.Call(uintptr(handleProcess), dllAddr, uintptr(unsafe.Pointer(&dllPathC[0])), uintptr(len(dllPathC)*2), 0)
	if r == 0 {
		return err, "Failed writing to process memory!"
	}
	r, _, err = procCreateRemoteThread.Call(uintptr(handleProcess), 0, 0, loadLibraryAddr, dllAddr, 0, 0)
	if r == 0 {
		return err, "Failed creating thread in process memory!"
	}
	handleThread := windows.Handle(r)
	event, err := windows.WaitForSingleObject(handleThread, 15000)
	if event == windows.WAIT_FAILED {
		return err, "Failed waiting for thread!"
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		return errors.New("WAIT_TIMEOUT"), "Failed while waiting for thread: timeout!"
	}
	if event != windows.WAIT_OBJECT_0 {
		return err, "Failed waiting for thread: unknown error!"
	}
	defer windows.CloseHandle(handleThread)
	var handleDll windows.Handle
	r, _, err = procGetExitCodeThread.Call(uintptr(handleThread), uintptr(unsafe.Pointer(&handleDll)))
	if r == 0 {
		return err, "Failed getting thread exit code!"
	}
	if handleDll == 0 {
		return errors.New("dll handle is nil"), "Failed loading library in process!"
	}

	// ignore error, too late to show an error message
	_, _, _ = procEnumWindows.Call(uintptr(C.cEnumWindowCallbackSetName), uintptr(unsafe.Pointer(&pid)))

	return nil, ""
}

func update() bool {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
	r, err := httpClient.Get("https://api.github.com/repos/delthas/autopunch/releases")
	if err != nil {
		// throw error even if the user is just disconnected from the internet
		dialog("Warning", "Error while checking for updates.\nError: "+err.Error(), walk.MsgBoxIconWarning)
		return false
	}
	var releases []struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		Assets  []struct {
			Name        string `json:"name"`
			DownloadUrl string `json:"browser_download_url"`
			Size        int64  `json:"size"`
		} `json:"assets"`
	}
	var dw bytes.Buffer
	dr := io.TeeReader(r.Body, &dw)
	decoder := json.NewDecoder(dr)
	err = decoder.Decode(&releases)
	r.Body.Close()
	if err != nil {
		ioutil.ReadAll(dr)
		var message struct {
			Message string `json:"message"`
		}
		decoder = json.NewDecoder(&dw)
		errMessage := decoder.Decode(&message)
		if errMessage != nil {
			dialog("Warning", "Error while processing updates information.\nError: "+err.Error(), walk.MsgBoxIconWarning)
		} else {
			dialog("Warning", "Error while processing updates information.\nError message: "+message.Message, walk.MsgBoxIconWarning)
		}
		return false
	}
	var assetName string
	if runtime.GOARCH == "amd64" {
		assetName = "autopunch.win64.exe"
	} else {
		assetName = "autopunch.win32.exe"
	}
	for _, v := range releases {
		if v.TagName == version {
			return false
		}
		for _, asset := range v.Assets {
			if asset.Name != assetName {
				continue
			}
			r, err = httpClient.Get(asset.DownloadUrl)
			if err != nil {
				dialog("Warning", "Error while downloading update.\nError: "+err.Error(), walk.MsgBoxIconWarning)
				return false
			}
			f, err := ioutil.TempFile("", "")
			if err != nil {
				r.Body.Close()
				dialog("Warning", "Error while creating file for downloading update.\nError: "+err.Error(), walk.MsgBoxIconWarning)
				return false
			}
			pr := progress.NewReader(r.Body)

			var done bool
			var dw *walk.Dialog
			var lb *walk.Label
			var pb *walk.ProgressBar
			mw.Synchronize(func() {
				_, err = Dialog{
					AssignTo: &dw,
					Title:    "autopunch " + version + " (by delthas)",
					MinSize:  Size{Width: 300, Height: 150},
					Size:     Size{Width: 400, Height: 200},
					Layout:   VBox{},
					Children: []Widget{
						Label{
							AssignTo: &lb,
							Text:     "Update found! Downlading update...\nAutopunch will restart itself automatically when finished.",
						},
						ProgressBar{
							AssignTo: &pb,
							MinValue: 0,
							MaxValue: 100000,
						},
					},
				}.Run(mw)
				if !done {
					os.Exit(0) // good enough for now
				}
			})
			go func() {
				ctx := context.Background()
				progressChan := progress.NewTicker(ctx, pr, asset.Size, 100*time.Millisecond)
				for p := range progressChan {
					if pb != nil {
						pb.Synchronize(func() {
							pb.SetValue(int(p.Percent() * float64(pb.MaxValue()) / 100))
						})
					}
					if lb != nil {
						text := fmt.Sprintf("Update found! Downlading update, remaining: %v\nAutopunch will restart itself automatically when finished.", p.Remaining().Round(time.Second))
						lb.Synchronize(func() {
							lb.SetText(text)
						})
					}
				}
			}()
			_, err = io.Copy(f, pr)
			done = true
			r.Body.Close()
			f.Close()
			dw.Close(0)
			mw.SetVisible(false)
			if err != nil {
				dialog("Warning", "Error while downloading update to file.\nError: "+err.Error(), walk.MsgBoxIconWarning)
				return false
			}

			renamePath := ""
			for i := 0; i < 10; i++ {
				renamePath = filepath.Join(os.TempDir(), "autopunch.old."+strconv.Itoa(1000000000 + rand.Intn(1000000000))[1:]+".exe")
				err = os.Rename(autopunchPath, renamePath)
				if err == nil {
					break
				}
			}
			if err != nil {
				for i := 0; i < 10; i++ {
					renamePath = filepath.Join(filepath.Dir(autopunchPath), "autopunch.old."+strconv.Itoa(1000000000 + rand.Intn(1000000000))[1:]+".exe")
					err = os.Rename(autopunchPath, renamePath)
					if err == nil {
						break
					}
				}
				if err != nil {
					dialog("Warning", "Error while updating, when moving current file.\nError: "+err.Error(), walk.MsgBoxIconWarning)
					return false
				}
			}

			err = os.Rename(f.Name(), autopunchPath)
			if err != nil {
				err = moveFile(f.Name(), autopunchPath)
				if err != nil {
					// try moving the old file back in case of error
					_ = os.Rename(renamePath, autopunchPath)
					dialog("Warning", "Error while updating, when moving downloaded file.\nError: "+err.Error(), walk.MsgBoxIconWarning)
					return false
				}
				time.Sleep(500 * time.Millisecond)
			}

			go func() {
				cmd := exec.Command(autopunchPath, os.Args[1:]...)
				cmd.Env = append(os.Environ(), "AUTOPUNCH_OLD="+renamePath)
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}()
			return true
		}
	}
	return false
}

func dialog(title string, description string, style walk.MsgBoxStyle) {
	if mw != nil && mw.Visible() {
		walk.MsgBox(mw, title, description, style)
	} else {
		walk.MsgBox(nil, title, description, style)
	}
}

const customVersion = "[Custom Build]"

var version string
var autopunchPath string

var mw *walk.MainWindow

func main() {
	if version == "" {
		version = customVersion
	}

	fmt.Println("autopunch " + version + " (by delthas)")

	rand.Seed(time.Now().UnixNano())
	exe, err := os.Executable()
	if err != nil {
		dialog("Warning", "Finding autopunch file failed! The game won't be able to update.", walk.MsgBoxIconWarning)
	} else {
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			dialog("Warning", "Finding autopunch file failed (resolving symlinks)! The game won't be able to update.", walk.MsgBoxIconWarning)
		} else {
			autopunchPath = exe
			processExcludes = append(processExcludes, filepath.Base(exe))
		}
	}

	if oldPath := os.Getenv("AUTOPUNCH_OLD"); oldPath != "" {
		time.Sleep(500 * time.Millisecond)
		// cleanup old update file, ignore error
		os.Remove(oldPath)
	}

	model := &processModel{}

	var cb *walk.CheckBox
	var lb *walk.ListBox

	err = MainWindow{
		AssignTo: &mw,
		Visible:  false,
		Title:    "autopunch " + version + " (by delthas)",
		MinSize:  Size{Width: 600, Height: 400},
		Size:     Size{Width: 800, Height: 600},
		Layout:   VBox{},
		Children: []Widget{
			ListBox{
				AssignTo: &lb,
				Model:    model,
				OnItemActivated: func() {
					go func() {
						inject(model.items[lb.CurrentIndex()].pid, cb.Checked())
					}()
				},
			},
			PushButton{
				Text: "Refresh",
				OnClicked: func() {
					go func() {
						refresh(model, lb)
						model.ItemsReset()
					}()
				},
			},
			PushButton{
				Text: "Punch!",
				OnClicked: func() {
					go func() {
						inject(model.items[lb.CurrentIndex()].pid, cb.Checked())
					}()
				},
			},
			CheckBox{
				AssignTo: &cb,
				Text:     "Debug Logs (if you have issues)",
				Checked:  false,
			},
		},
	}.Create()
	if err != nil {
		panic(err)
	}

	go func() {
		if version != customVersion && autopunchPath != "" {
			if update() {
				mw.Close()
				return
			}
		}

		mw.Synchronize(func() {
			mw.SetVisible(true)
		})
		err := refresh(model, lb)
		if err != nil {
			panic(err)
		}
	}()

	r := mw.Run()
	if r != 0 {
		os.Exit(r)
	}
}

func moveFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		in.Close()
		return err
	}

	_, err = io.Copy(out, in)
	out.Close()
	in.Close()
	if err != nil {
		return err
	}

	os.Remove(src)
	return nil
}
