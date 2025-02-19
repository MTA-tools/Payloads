# Payload generation script
## About
This repo contains a script that uses the placeholder files (templates) to create a variety of meterpreter payloads. The script automatically gets your tun0 interface IP address and uses port 443.

## Payloads
- PowerShell download-execute cradle
- PowerShell base64 encoded download-execute cradle
- Binary meterpreter shellcode
- PowerShell meterpreter shellcode
- VBA meterpreter shellcode
- C# meterpreter shellcode
- Encrypted C# meterpreter shellcode
- ASPX meterpreter payload
- DLL meterpreter payload
- EXE meterpreter payload
- ELF meterpreter payload
- PowerShell shellcode runner
- PowerShell shellcode loader
- VBA shellcode runner
- VBA shellcode loader
- C# shellcode runner

These payloads will be placed in `/var/www/html/shellcode` and `/var/www/html/payloads` for quick use with an Apache Web Server.

## Usage
```
sudo ./payloads.sh
```
