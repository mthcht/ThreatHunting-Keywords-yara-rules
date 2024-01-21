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
        $string1 = /Backdoor\.ASP\.FUZZSHELL\.A/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string2 = /Backdoor\.ASP\.WEBSHELL\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string3 = /Backdoor\.PHP\.WebShell\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string4 = /Backdoor\/Win\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string5 = /Backdoor:JS\// nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string6 = /Backdoor:Linux/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string7 = /Backdoor:MSIL\/SectopRAT/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string8 = /Backdoor:Python/ nocase ascii wide
        // Description: Antivirus signature - a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: N/A
        $string9 = /Backdoor:Python\// nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string10 = /Backdoor:VBS\// nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string11 = /Backdoor:Win32/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string12 = /Backdoor:Win64/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string13 = /Backdoor:Win64\/CobaltStrike/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string14 = /Behavior:Win32\/CobaltStrike/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string15 = /BKDR_JSPSHELL\./ nocase ascii wide
        // Description: Antivirus signature_keyword for hacktool clearing logs
        // Reference: N/A
        $string16 = /Clearlogs/ nocase ascii wide
        // Description: windows defender antivirus signature for UAC bypass
        // Reference: N/A
        $string17 = /CobaltStrike\.LJ\!MTB/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string18 = /Exploit:Python\// nocase ascii wide
        // Description: hacktool keyword. a repository could be named as such. o AV signature
        // Reference: N/A
        $string19 = /hacktool/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string20 = /HackTool\.ASP\..{0,1000}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string21 = /HackTool\.HTML\..{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string22 = /HackTool\.Java\..{0,1000}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string23 = /Hacktool\.Linux/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string24 = /HackTool\.PHP\..{0,1000}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string25 = /Hacktool\.Windows/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string26 = /Hacktool\/Win\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string27 = /HackTool:Linux/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string28 = /HackTool:MSIL/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string29 = /HackTool:PowerShell/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string30 = /HackTool:PowerShell\// nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string31 = /HackTool:Python/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string32 = /HackTool:Python\// nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string33 = /Hacktool:Script\// nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string34 = /Hacktool:SH/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string35 = /Hacktool:VBA/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string36 = /HackTool:VBS/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string37 = /HackTool:Win32/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string38 = /HackTool:Win32/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string39 = /HackTool:Win64/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string40 = /HackTool:Win64/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string41 = /HackTool:Win64\/CobaltStrike/ nocase ascii wide
        // Description: Antivirus signature_keyword for hacktool
        // Reference: N/A
        $string42 = /HKTL/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string43 = /HKTL_NETCAT/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string44 = /HTool/ nocase ascii wide
        // Description: Generic hacktool Engine signature
        // Reference: N/A
        $string45 = /HTool\/WCE/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string46 = /impacket/ nocase ascii wide
        // Description: Dump LSASS memory through a process snapshot (-r) avoiding interacting with it directly
        // Reference: lsass dump malware signature
        $string47 = /Lsass\-Mdump/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string48 = /MSFPsExeCommand/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string49 = /PowerShell\/HackTool/ nocase ascii wide
        // Description: highly revelant Antivirus signature. phishing tools
        // Reference: N/A
        $string50 = /PShlSpy/ nocase ascii wide
        // Description: highly revelant Antivirus signature. Programs classified as PSWTool can be used to view or restore forgotten often hidden passwords. They can also be used with malicious intent. even though the programs themselves have no malicious payload.
        // Reference: N/A
        $string51 = /PSWtool/ nocase ascii wide
        // Description: Antivirus signature - a tool used within a command-line interface on 64bit Windows computers to extract the NTLM (LanMan) hashes from LSASS.exe in memory. This tool may be used in conjunction with malware or other penetration testing tools to obtain credentials for use in Windows authentication systems
        // Reference: N/A
        $string52 = /PWDump\s/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string53 = /PWS:Win32\/Mpass/ nocase ascii wide
        // Description: Antiviurs signature_keyword for ransomware
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver/indicators-blackcat-ransomware-deploys-new-signed-kernel-driver.txt
        $string54 = /Ransom\.Win32\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string55 = /Ransom:Linux\/BlackBasta/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string56 = /Ransom:Win32/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string57 = /Ransom:Win32/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string58 = /Ransom:Win32\/BlackBasta/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string59 = /Ransom:Win64/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string60 = /Ransom_Petya/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string61 = /Ransom_WCRY/ nocase ascii wide
        // Description: Antiviurs signature_keyword for remote administration tools 
        // Reference: N/A
        $string62 = /RemAdm/ nocase ascii wide
        // Description: Antiviurs signature_keyword for ransomware
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/23/e/blackcat-ransomware-deploys-new-signed-kernel-driver/indicators-blackcat-ransomware-deploys-new-signed-kernel-driver.txt
        $string63 = /Rootkit\.Win64\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string64 = /SupportScam:Win32/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string65 = /Tojan:Win32\/Goodkit/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string66 = /TROJ_ZIPBOMB\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string67 = /Trojan\.Linux/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string68 = /Trojan\.Win32\..{0,1000}\./ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string69 = /Trojan\.Win64/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string70 = /Trojan\.WinGo/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string71 = /Trojan\/Win32/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string72 = /Trojan\/Win64/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string73 = /Trojan:PowerShell/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string74 = /Trojan:PowerShell\/BatLoader/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string75 = /Trojan:Python\/BatLoader/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string76 = /Trojan:Win32/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string77 = /Trojan:Win32\/Batloader/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string78 = /Trojan:Win32\/EugenLoader/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string79 = /Trojan:Win32\/Gozi/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string80 = /Trojan:Win32\/IceId/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string81 = /Trojan:Win32\/Smokeloader/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string82 = /Trojan:Win32\/Trickbot/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string83 = /Trojan:Win64/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string84 = /Trojan:Win64\/IcedID/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string85 = /Trojan:Win64\/IceId/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string86 = /Trojan:Win64\/Lumma/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string87 = /TrojanDownloader:PowerShell\/EugenLoader/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string88 = /TrojanDownloader:PowerShell\/Malgent/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string89 = /TrojanDropper:PowerShell\// nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string90 = /TrojanDropper:Win32/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string91 = /TrojanSpy\.Win64/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string92 = /TrojanSpy:MSIL\/JSSLoader/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string93 = /TrojanSpy:MSIL\/JSSLoader/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string94 = /VirTool.{0,1000}RemoteExec/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string95 = /VirTool:MSIL/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string96 = /VirTool:PowerShell\/Dipadz\./ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string97 = /VirTool:Win32/ nocase ascii wide
        // Description: AV signature often associated with C2 communications (cobaltstrike for example)
        // Reference: N/A
        $string98 = /VirTool:Win32\/RemoteExec/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string99 = /Win32\.Trojan/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string100 = /Win32\/Goodkit/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string101 = /Win32\/IceId/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string102 = /Win32\/Mikatz/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string103 = /Win32\/Trickbot/ nocase ascii wide
        // Description: windows defender antivirus signature for UAC bypass
        // Reference: N/A
        $string104 = /Win32\/UACBypass/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string105 = /Win32:Trojan/ nocase ascii wide
        // Description: antivirus signatures
        // Reference: N/A
        $string106 = /Win64\/IceId/ nocase ascii wide
        // Description: AV signature for exploitation tools
        // Reference: N/A
        $string107 = /Win64\/Mikatz/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string108 = /Windows\.Hacktool\./ nocase ascii wide

    condition:
        any of them
}
