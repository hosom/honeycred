/*

Honeycred is used to stage credentials into a live running process to be used
as bait to detect credential abuse within Windows domains.

NOTE: Most applications that inject honey credentials terminate after making a
call to advapi32.CreateProcessWithLogonW. Unfortunately, after MS16-137, this
stopped being an option. This patch more aggressively cleans up credentials 
from lsass.

To avoid credentials from being cleaned up, this application forks and runs 
silently.

*/

package main

import (
	"flag"
	"strings"
	"os"
	"syscall"
	"unsafe"
	"runtime"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	procCreateProcessWithLogonW   = advapi32.NewProc("CreateProcessWithLogonW")
)


const (
	// Use only network credentials for login
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x00000002
	// The new process does not inherit the error mode of the calling process.
	// Instead, CreateProcessWithLogonW gives the new process the current 
	// default error mode.
	CREATE_DEFAULT_ERROR_MODE uint32 = 0x04000000
	// Flag parameter that indicates to use the value set in ShowWindow
	STARTF_USESHOWWINDOW = 0x00000001
	// Tell windows not to show the window 
	ShowWindow = 0
)
// CreateProcessWithLogonW is a wrapper around the matching advapi32.dll 
// function. This allows the running process to launch a process as a 
// different user. It can also be used to stage credentials. 
func CreateProcessWithLogonW(
	username *uint16,
	domain *uint16,
	password *uint16,
	logonFlags uint32,
	applicationName *uint16,
	commandLine *uint16,
	creationFlags uint32,
	environment *uint16,
	currentDirectory *uint16,
	startupInfo *syscall.StartupInfo,
	processInformation *syscall.ProcessInformation) error {
	r1, _, e1 := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(environment)), // env
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInformation)))
	runtime.KeepAlive(username)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(password)
	runtime.KeepAlive(applicationName)
	runtime.KeepAlive(commandLine)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(currentDirectory)
	runtime.KeepAlive(startupInfo)
	runtime.KeepAlive(processInformation)
	if int(r1) == 0 {
		return os.NewSyscallError("CreateProcessWithLogonW", e1)
	}
	return nil
}

// ListToEnvironmentBlock converts a list of string pointers to a Windows
// environment block. 
func ListToEnvironmentBlock(list *[]string) *uint16 {
	if list == nil {
		return nil
	}

	size := 1
	for _, v := range *list {
		size += len(syscall.StringToUTF16(v))
	}

	result := make([]uint16, size)

	tail := 0

	for _, v := range *list {
		uline := syscall.StringToUTF16(v)
		copy(result[tail:], uline)
		tail += len(uline)
	}

	result[tail] = 0

	return &result[0]
}

func main() {

	user := flag.String("u", `contoso.com\svc_dlp`, "")
	pw := flag.String("pw", `foobar9000`, "")
	path := flag.String("path", `.\agent.exe`, "")
	flag.Parse()

	userSplit := strings.Split(*user, `\`)
	var logonDomain string
	if ( len(userSplit) > 1 ) {
		logonDomain = userSplit[0]
	} else {
		logonDomain = ""
	}
	user = &userSplit[len(userSplit)-1]

	username := syscall.StringToUTF16Ptr(*user)
	domain := syscall.StringToUTF16Ptr(logonDomain)
	password := syscall.StringToUTF16Ptr(*pw)
	logonFlags := LOGON_NETCREDENTIALS_ONLY
	applicationName := syscall.StringToUTF16Ptr(*path)
	commandLine := syscall.StringToUTF16Ptr(``)
	creationFlags := CREATE_DEFAULT_ERROR_MODE
	environment := ListToEnvironmentBlock(nil)
	currentDirectory := syscall.StringToUTF16Ptr(`c:\`)

	startupInfo := &syscall.StartupInfo{}
	startupInfo.ShowWindow = ShowWindow
	startupInfo.Flags = startupInfo.Flags | STARTF_USESHOWWINDOW
	processInfo := &syscall.ProcessInformation{}

	_ = CreateProcessWithLogonW(
		username,
		domain,
		password,
		logonFlags,
		applicationName,
		commandLine,
		creationFlags,
		environment,
		currentDirectory,
		startupInfo,
		processInfo)
}