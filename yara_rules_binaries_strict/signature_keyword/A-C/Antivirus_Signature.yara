rule Antivirus_Signature
{
    meta:
        description = "Detection patterns for the tool 'Antivirus Signature' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Antivirus Signature"
        rule_category = "signature_keyword"

    strings:
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string1 = /Backdoor\.ASP/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string2 = /Backdoor\.ASP\.FUZZSHELL\.A/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string3 = /Backdoor\.ASP\.WEBSHELL\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string4 = /Backdoor\.Cobalt/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string5 = /Backdoor\.JSP/ nocase ascii wide
        // Description: AV signature of noodlerat malware
        // Reference: N/A
        $string6 = /Backdoor\.Linux/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string7 = /Backdoor\.PHP/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string8 = /Backdoor\.PHP\.WebShell\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string9 = /Backdoor\/Win\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string10 = "Backdoor:JS/" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string11 = "Backdoor:Linux" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string12 = "Backdoor:MacOS" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string13 = "Backdoor:MSIL/AsyncRat" nocase ascii wide
        // Description: AV signature for exploitation tools for Quasar.exe
        // Reference: N/A
        $string14 = "Backdoor:MSIL/Quasar" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string15 = "Backdoor:MSIL/SectopRAT" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string16 = "Backdoor:PHP/" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string17 = "Backdoor:Python" nocase ascii wide
        // Description: Antivirus signature - a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: N/A
        $string18 = "Backdoor:Python/" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string19 = "Backdoor:VBS/" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string20 = "Backdoor:Win32" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string21 = "Backdoor:Win64" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string22 = "Backdoor:Win64/CobaltStrike" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string23 = "Behavior:Win32/CobaltStrike" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string24 = /BKDR_JSPSHELL\./ nocase ascii wide
        // Description: Antivirus signature_keyword for hacktool clearing logs
        // Reference: N/A
        $string25 = "Clearlogs" nocase ascii wide
        // Description: windows defender antivirus signature for UAC bypass
        // Reference: N/A
        $string26 = /CobaltStrike\.LJ\!MTB/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string27 = "Exploit:Python/" nocase ascii wide
        // Description: Antiviurs signature_keyword observed with meterpreter exploits
        // Reference: N/A
        $string28 = "Exploit:Win32/CVE-" nocase ascii wide
        // Description: Antiviurs signature_keyword observed with meterpreter exploits
        // Reference: N/A
        $string29 = "Exploit:Win64/CVE-" nocase ascii wide
        // Description: hacktool keyword. a repository could be named as such. o AV signature
        // Reference: N/A
        $string30 = "hacktool" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string31 = /HackTool\.ASP\..{0,100}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string32 = /HackTool\.HTML\..{0,100}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string33 = /HackTool\.Java\..{0,100}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string34 = /Hacktool\.Linux/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string35 = /HackTool\.PHP\..{0,100}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string36 = /Hacktool\.Windows/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string37 = /Hacktool\/Win\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string38 = "HackTool:Linux" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string39 = "HackTool:MSIL" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string40 = "HackTool:PowerShell" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string41 = "HackTool:PowerShell/" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string42 = "HackTool:Python" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string43 = "HackTool:Python/" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string44 = "Hacktool:Script/" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string45 = "Hacktool:SH" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string46 = "Hacktool:VBA" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string47 = "HackTool:VBS" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string48 = "HackTool:Win32" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string49 = "HackTool:Win32" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string50 = "HackTool:Win64" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string51 = "HackTool:Win64" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string52 = "HackTool:Win64/CobaltStrike" nocase ascii wide
        // Description: Antivirus signature_keyword for hacktool
        // Reference: N/A
        $string53 = "HKTL" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string54 = "HKTL_NETCAT" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string55 = "HTool" nocase ascii wide
        // Description: Generic hacktool Engine signature
        // Reference: N/A
        $string56 = "HTool/WCE" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string57 = "impacket" nocase ascii wide
        // Description: AV signature of noodlerat malware
        // Reference: N/A
        $string58 = /Linux\.Backdoor/ nocase ascii wide
        // Description: Dump LSASS memory through a process snapshot (-r) avoiding interacting with it directly
        // Reference: lsass dump malware signature
        $string59 = "Lsass-Mdump" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string60 = "MSFPsExeCommand" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string61 = "PowerShell/HackTool" nocase ascii wide
        // Description: highly revelant Antivirus signature. phishing tools
        // Reference: N/A
        $string62 = "PShlSpy" nocase ascii wide
        // Description: highly revelant Antivirus signature. Programs classified as PSWTool can be used to view or restore forgotten often hidden passwords. They can also be used with malicious intent. even though the programs themselves have no malicious payload.
        // Reference: N/A
        $string63 = "PSWtool" nocase ascii wide
        // Description: Antivirus signature - a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: N/A
        $string64 = "PWDump " nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string65 = "PWS:Win32/Mpass" nocase ascii wide
        // Description: Antiviurs signature_keyword for ransomware
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver/indicators-blackcat-ransomware-deploys-new-signed-kernel-driver.txt
        $string66 = /Ransom\.Win32\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string67 = "Ransom:Linux/BlackBasta" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string68 = "Ransom:Win32" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string69 = "Ransom:Win32" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string70 = "Ransom:Win32/BlackBasta" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string71 = "Ransom:Win64" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string72 = "Ransom_Petya" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string73 = "Ransom_WCRY" nocase ascii wide
        // Description: Antiviurs signature_keyword for remote administration tools 
        // Reference: N/A
        $string74 = "RemAdm" nocase ascii wide
        // Description: Antiviurs signature_keyword for ransomware
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver/indicators-blackcat-ransomware-deploys-new-signed-kernel-driver.txt
        $string75 = /Rootkit\.Win64\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string76 = "SupportScam:Win32" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string77 = "Tojan:Win32/Goodkit" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string78 = /TROJ_ZIPBOMB\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string79 = /Trojan\.Linux/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string80 = /Trojan\.Win32\..{0,100}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string81 = /Trojan\.Win64/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string82 = /Trojan\.WinGo/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string83 = "Trojan/Win32" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string84 = "Trojan/Win64" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string85 = "Trojan:MacOS" nocase ascii wide
        // Description: Antiviurs signature_keyword for xeno rat client.exe
        // Reference: N/A
        $string86 = /Trojan\:MSIL\/Dothetuk\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string87 = "Trojan:PowerShell" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string88 = "Trojan:PowerShell/BatLoader" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string89 = "Trojan:Python/BatLoader" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string90 = "Trojan:Win32" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string91 = "Trojan:Win32/Batloader" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string92 = "Trojan:Win32/EugenLoader" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string93 = "Trojan:Win32/Gozi" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string94 = "Trojan:Win32/IceId" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string95 = "Trojan:Win32/Smokeloader" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string96 = "Trojan:Win32/Trickbot" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string97 = "Trojan:Win64" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string98 = "Trojan:Win64/IcedID" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string99 = "Trojan:Win64/IceId" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string100 = "Trojan:Win64/Lumma" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string101 = "TrojanDownloader:PowerShell/EugenLoader" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string102 = "TrojanDownloader:PowerShell/Malgent" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string103 = "TrojanDropper:PowerShell/" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string104 = "TrojanDropper:Win32" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string105 = /TrojanSpy\.Win64/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string106 = "TrojanSpy:MSIL/JSSLoader" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string107 = "TrojanSpy:MSIL/JSSLoader" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string108 = /VirTool.{0,100}RemoteExec/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string109 = "VirTool:MSIL" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string110 = /VirTool\:PowerShell\/Dipadz\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string111 = "VirTool:Win32" nocase ascii wide
        // Description: AV signature often associated with C2 communications (cobaltstrike for example)
        // Reference: N/A
        $string112 = "VirTool:Win32/RemoteExec" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string113 = /Win32\.Trojan/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string114 = "Win32/Goodkit" nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string115 = "Win32/IceId" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string116 = "Win32/Mikatz" nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string117 = "Win32/Trickbot" nocase ascii wide
        // Description: windows defender antivirus signature for UAC bypass
        // Reference: N/A
        $string118 = "Win32/UACBypass" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string119 = "Win32:Trojan" nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string120 = "Win64/IceId" nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string121 = "Win64/Mikatz" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string122 = /Windows\.Hacktool\./ nocase ascii wide
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
