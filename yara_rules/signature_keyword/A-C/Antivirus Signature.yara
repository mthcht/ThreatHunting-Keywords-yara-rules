rule Antivirus_Signature
{
    meta:
        description = "Detection patterns for the tool 'Antivirus Signature' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Antivirus Signature"
        rule_category = "signature_keyword"

    strings:
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string1 = /.{0,1000}Backdoor\.ASP\.FUZZSHELL\.A.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string2 = /.{0,1000}Backdoor\.ASP\.WEBSHELL\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string3 = /.{0,1000}Backdoor\.PHP\.WebShell\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string4 = /.{0,1000}Backdoor\/Win\..{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string5 = /.{0,1000}Backdoor:JS\/.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string6 = /.{0,1000}Backdoor:Linux.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string7 = /.{0,1000}Backdoor:Python.{0,1000}/ nocase ascii wide
        // Description: Antivirus signature - a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: N/A
        $string8 = /.{0,1000}Backdoor:Python\/.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string9 = /.{0,1000}Backdoor:VBS\/.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string10 = /.{0,1000}Backdoor:Win32.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string11 = /.{0,1000}Backdoor:Win64.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string12 = /.{0,1000}BKDR_JSPSHELL\..{0,1000}/ nocase ascii wide
        // Description: Antivirus signature_keyword for hacktool clearing logs
        // Reference: N/A
        $string13 = /.{0,1000}Clearlogs.{0,1000}/ nocase ascii wide
        // Description: windows defender antivirus signature for UAC bypass
        // Reference: N/A
        $string14 = /.{0,1000}CobaltStrike\.LJ\!MTB.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string15 = /.{0,1000}Exploit:Python\/.{0,1000}/ nocase ascii wide
        // Description: hacktool keyword. a repository could be named as such. o AV signature
        // Reference: N/A
        $string16 = /.{0,1000}hacktool.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string17 = /.{0,1000}HackTool\.ASP\..{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string18 = /.{0,1000}HackTool\.HTML\..{0,1000}\..{0,1000}.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string19 = /.{0,1000}HackTool\.Java\..{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string20 = /.{0,1000}Hacktool\.Linux.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string21 = /.{0,1000}HackTool\.PHP\..{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string22 = /.{0,1000}Hacktool\.Windows.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string23 = /.{0,1000}Hacktool\/Win\..{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string24 = /.{0,1000}HackTool:Linux.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string25 = /.{0,1000}HackTool:MSIL.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string26 = /.{0,1000}HackTool:PowerShell.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string27 = /.{0,1000}HackTool:PowerShell\/.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string28 = /.{0,1000}HackTool:Python.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string29 = /.{0,1000}HackTool:Python\/.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string30 = /.{0,1000}Hacktool:Script\/.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string31 = /.{0,1000}Hacktool:SH.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string32 = /.{0,1000}Hacktool:VBA.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string33 = /.{0,1000}HackTool:VBS.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string34 = /.{0,1000}HackTool:Win32.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string35 = /.{0,1000}HackTool:Win32.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string36 = /.{0,1000}HackTool:Win64.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string37 = /.{0,1000}HackTool:Win64.{0,1000}/ nocase ascii wide
        // Description: Antivirus signature_keyword for hacktool
        // Reference: N/A
        $string38 = /.{0,1000}HKTL.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string39 = /.{0,1000}HKTL_NETCAT.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string40 = /.{0,1000}HTool.{0,1000}/ nocase ascii wide
        // Description: Generic hacktool Engine signature
        // Reference: N/A
        $string41 = /.{0,1000}HTool\/WCE.{0,1000}/ nocase ascii wide
        // Description: Dump LSASS memory through a process snapshot (-r) avoiding interacting with it directly
        // Reference: lsass dump malware signature
        $string42 = /.{0,1000}Lsass\-Mdump.{0,1000}/ nocase ascii wide
        // Description: highly revelant Antivirus signature. phishing tools
        // Reference: N/A
        $string43 = /.{0,1000}PShlSpy.{0,1000}/ nocase ascii wide
        // Description: highly revelant Antivirus signature. Programs classified as PSWTool can be used to view or restore forgotten often hidden passwords. They can also be used with malicious intent. even though the programs themselves have no malicious payload.
        // Reference: N/A
        $string44 = /.{0,1000}PSWtool.{0,1000}/ nocase ascii wide
        // Description: Antivirus signature - a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: N/A
        $string45 = /.{0,1000}PWDump\s.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string46 = /.{0,1000}PWS:Win32\/Mpass.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword for ransomware
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver/indicators-blackcat-ransomware-deploys-new-signed-kernel-driver.txt
        $string47 = /.{0,1000}Ransom\.Win32\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string48 = /.{0,1000}Ransom:Win32.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string49 = /.{0,1000}Ransom:Win32.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string50 = /.{0,1000}Ransom:Win64.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string51 = /.{0,1000}Ransom_Petya.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string52 = /.{0,1000}Ransom_WCRY.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword for remote administration tools 
        // Reference: N/A
        $string53 = /.{0,1000}RemAdm.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword for ransomware
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver/indicators-blackcat-ransomware-deploys-new-signed-kernel-driver.txt
        $string54 = /.{0,1000}Rootkit\.Win64\..{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string55 = /.{0,1000}SupportScam:Win32.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string56 = /.{0,1000}Tojan:Win32\/Goodkit.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string57 = /.{0,1000}TROJ_ZIPBOMB\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string58 = /.{0,1000}Trojan\.Linux.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string59 = /.{0,1000}Trojan\.Win32\..{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string60 = /.{0,1000}Trojan\.Win64.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string61 = /.{0,1000}Trojan\.WinGo.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string62 = /.{0,1000}Trojan\/Win32.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string63 = /.{0,1000}Trojan\/Win64.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string64 = /.{0,1000}Trojan:PowerShell.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string65 = /.{0,1000}Trojan:Win32.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string66 = /.{0,1000}Trojan:Win32\/IceId.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string67 = /.{0,1000}Trojan:Win32\/Trickbot.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string68 = /.{0,1000}Trojan:Win64.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string69 = /.{0,1000}Trojan:Win64\/IceId.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string70 = /.{0,1000}TrojanDropper:Win32.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string71 = /.{0,1000}TrojanSpy\.Win64.{0,1000}/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string72 = /.{0,1000}TrojanSpy:MSIL\/JSSLoader.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string73 = /.{0,1000}TrojanSpy:MSIL\/JSSLoader.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string74 = /.{0,1000}VirTool:MSIL.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string75 = /.{0,1000}VirTool:Win32.{0,1000}/ nocase ascii wide
        // Description: AV signature often associated with C2 communications (cobaltstrike for example)
        // Reference: N/A
        $string76 = /.{0,1000}VirTool:Win32\/RemoteExec.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string77 = /.{0,1000}Win32\.Trojan.{0,1000}/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string78 = /.{0,1000}Win32\/Goodkit.{0,1000}/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string79 = /.{0,1000}Win32\/IceId.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string80 = /.{0,1000}Win32\/Mikatz.{0,1000}/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string81 = /.{0,1000}Win32\/Trickbot.{0,1000}/ nocase ascii wide
        // Description: windows defender antivirus signature for UAC bypass
        // Reference: N/A
        $string82 = /.{0,1000}Win32\/UACBypass.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string83 = /.{0,1000}Win32:Trojan.{0,1000}/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string84 = /.{0,1000}Win64\/IceId.{0,1000}/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string85 = /.{0,1000}Win64\/Mikatz.{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string86 = /.{0,1000}Windows\.Hacktool\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
