rule Python_Rootkit
{
    meta:
        description = "Detection patterns for the tool 'Python-Rootkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Python-Rootkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string1 = " -ListMetasploitPayloads" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string2 = "\"Injecting shellcode into PowerShell\"" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string3 = "# download virRu5" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string4 = "# execute virRu5" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string5 = /\/Python\-Rootkit\.git/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string6 = /\\Python\-Rootkit\\/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string7 = "0xIslamTaha/Python-Rootkit" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string8 = "44ae9957842a29e354e2a64874bad57eb1790ed15ce345184ee8773c1e380e3a" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string9 = "55ac39fc6d45b2e315df43a71380ca8c20e62e28b9531e56d920e6f45103388d" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string10 = /A13BGD\s\=\s\sbase64\.b64decode\(A13BGD\)/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string11 = "About to download Metasploit payload " nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string12 = "Ck5PX0lQX0hPU1QgPSAnZ29vZ2xlY2hyb21lYXV0by5zZXJ2ZWlyYy5jb20nCkxIT1NUID0gJzE5Mi4xNjguMS4zJwpMUE9SVCA9IDQ0MwpUSU1FX1NMRUVQID0gMTAKClRFTVBfUEFUSCA9IHRlbXBmaWxlLmdldHRlbXBkaXIoKQpSRUdfUEFUSCA9IHIiU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuIgpSRUdfTkFNRSA9ICJHb29nbGVDaHJvbWVBdXRvTGF1bmNoXzk5MjEzNjYxMDJXRUFEMjEzMTJFU0FEMzEzMTIiClJFR19WQUxVRSA" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string13 = /Do\syou\swant\sto\slaunch\sthe\spayload\sfrom\sx86\sPowershell\?/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string14 = /dump_google_password\(\)/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string15 = /googlechromeauto\.serveirc\.com/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string16 = "GoogleChromeAutoLaunch_9921366102WEAD21312ESAD31312" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string17 = /http\:\/\/ec2\-52\-90\-251\-67\.compute\-1\.amazonaws\.com\/GoogleChromeAutoLaunch\.exe/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string18 = "Injecting shellcode into PID: " nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string19 = "Injecting shellcode into the running PowerShell process" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string20 = "Invoke-Shellcode -Payload " nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string21 = "Invoke-Shellcode -ProcessId " nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string22 = "Invoke-Shellcode -Shellcode " nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string23 = /Invoke\-Shellcode\.ps1/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string24 = "Q2s1UFgwbFFYMGhQVTFRZ1BTQW5aMjl2WjJ4bFkyaHliMjFsWVhWMGJ5NXpaWEoyWldseVl5NWpiMjBuQ2t4SVQxTlVJRDBnSnpFNU1pNHhOamd1TVM0ekp3cE1VRTlTVkNBOUlEUTBNd3BVU1UxRlgxTk1SVVZRSUQwZ01UQUtDbFJGVFZCZlVFRlVTQ0E5SUhSbGJYQm1hV3hsTG1kbGRIUmxiWEJrYVhJb0tRcFNSVWRmVUVGVVNDQTlJSElpVTI5bWRIZGhjbVZjVFdsa" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string25 = "Requesting meterpreter payload from https://" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string26 = "SELECT action_url, username_value, password_value FROM logins'" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string27 = "Shellcode injection complete!" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string28 = /socket\.gethostbyname\(NO_IP_HOST\)/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string29 = "Unable to inject 64-bit shellcode from within 32-bit Powershell" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string30 = "UTJzMVVGZ3diRkZZTUdoUVZURlJaMUJUUVc1YU1qbDJXako0YkZreWFIbGlNakZzV1ZoV01HSjVOWHBhV0VveVdsZHNlVmw1TldwaU1qQnVRMnQ0U1ZReFRsVkpSREJuU25wRk5VMXBOSGhPYW1kMVRWTTBla3AzY0UxVlJUbFRWa05CT1VsRVVUQk5kM0JWVTFVeFJsZ3hUazFTVlZaUlNVUXdaMDFVUVV0RGJGSkdWRlpDWmxWRlJsVlRRMEU1U1VoU2JHSllRbTFoVjN" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string31 = /viRu5\/GoogleChromeAutoLaunch\.py/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string32 = /viRu5\\GoogleChromeAutoLaunch\.py/ nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string33 = "VlZSS2VrMVdWa2RhTTJScFVtdGFXbFJWWkc5VlZscFZVbXhLWVUxVlNsVlZWbU14V1ZVeGNXSkVTbGhoYTI4d1dXdGFjbVZYUmtsaVIyeE9ZV3RhZWxZeFdtOVdNREZJVTJwV1QxZElRbWhXTUZaMlpWWmtjMXBJVG14V2JYY3hWR3hrZDJGVk1YRlJibFpTVFc1Uk1GVXhXbEpsUmxKelZtdHdVMUpGU25WVk1qVjNVbXMxVmsxWVFrOVRSMmhRV1ZjeGEwMVdVbGRVVkVKc" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string34 = "Vm14YVUxTXlWbkpOVm1SWFlUSlNhRlJVU2xOalJsWjBaRWRHV0dKR1NsZFhhMk0xVm14YWMyTkdXbFppV0doTVYxWlZlRlpzVG5OV2JGcFhZbFV4TkZZeFdsWmxSMDVZVTJ0V1ZHSkhhRzlaVkVrMFpERmtXR1JIUm1waVZscFpWVzEwYzJGV1NYbGxSVGxhVmpOU2FGcFhlRnBsUm1SMFQxWmtUbEpGV2twV1ZFcDNWakZSZUZwRmJGSmlWMmhZVkZWYVlVMXNjRmRY" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string35 = "VmxaU1MyVnJNVmRXYTJSaFRUSlNjRlZ0ZEdGWGJGSldXa2M1Vmxac2NGWlZiWGhMV1ZVeFZsTnNWbFpXYlUxNFYxWlZlR05YU2tWVGJHaG9ZVEk0ZDFkWGRHRmpiVlpZVW10c2FWSXllRTlaVjNSaFpXeFplRmR0T1ZkTlJFWkpWVEp3VjFReFpFbFJiV2hYVFVaYU1scFdXbXRqTVhCSlZHMTRWMkpZWTNoV1IzaHJaREpHVmsxWVJsSmliRnBUVkZjMVVrMUdWWGhYYkVw" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string36 = "VVRKek1WVkdaM2RpUmtaWlRVZG9VVlpVUmxKYU1VSlVVVmMxWVUxcWJESlhha28wWWtacmVXRkliR2xOYWtaelYxWm9WMDFIU2pWT1dIQmhWMFZ2ZVZkc1pITmxWbXcxVGxkd2FVMXFRblZSTW5RMFUxWlJlRlJzVmtwU1JFSnVVMjV3Ums1Vk1YQk9TR2hQWVcxa01WUldUVEJsYTNBelkwVXhWbEpVYkZSV2EwNUNUMVZzUlZWVVFrNWtNMEpXVlRGVmVGSnNaM2h" nocase ascii wide
        // Description: full undetectable python RAT which can bypass almost all antivirus and open a backdoor inside any windows machine which will establish a reverse https Metasploit connection to your listening machine
        // Reference: https://github.com/0xIslamTaha/Python-Rootkit
        $string37 = "windows/meterpreter/reverse_https" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
