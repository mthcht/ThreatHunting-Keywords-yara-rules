rule C2_related_tools
{
    meta:
        description = "Detection patterns for the tool 'C2 related tools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2 related tools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string1 = /.{0,1000}\sbeacon64\.bin\s.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string2 = /.{0,1000}\sNoPowerShell\..{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string3 = /.{0,1000}\s\-pe\-exp\-list\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string4 = /.{0,1000}\ssigflip\..{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string5 = /.{0,1000}\s\-U\smsf\s\-P\smsf\s.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string6 = /.{0,1000}\!wPkgPath\!.{0,1000}\!ak\!.{0,1000}/ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string7 = /.{0,1000}\/bypass_mod\/loader.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string8 = /.{0,1000}\/Cooolis\-ms\/.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string9 = /.{0,1000}\/DllExport\.bat.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string10 = /.{0,1000}\/nopowershell\/.{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string11 = /.{0,1000}\/ShellcodeFluctuation.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string12 = /.{0,1000}\/SigFlip\..{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string13 = /.{0,1000}\/SigFlip\/.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string14 = /.{0,1000}\/SigLoader\/.{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string15 = /.{0,1000}\/unhook\-bof.{0,1000}/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string16 = /.{0,1000}\\codeloader\.exe.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string17 = /.{0,1000}\\Cooolis\-ms\-Loader\\.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string18 = /.{0,1000}\\DllExport\.bat.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string19 = /.{0,1000}\\NoPowerShell\..{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string20 = /.{0,1000}\\tests\\beacon64\.bin.{0,1000}/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string21 = /.{0,1000}APC_Ijnect_Load\.nim.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string22 = /.{0,1000}BOFNET\.dll.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string23 = /.{0,1000}bofnet_execute\..{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string24 = /.{0,1000}bWV0YXNwbG9pdA\=\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string25 = /.{0,1000}c2hlbGxjb2Rl.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string26 = /.{0,1000}cGlwZW5hbWU9.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string27 = /.{0,1000}cmVmbGVjdGl2ZQ\=\=.{0,1000}/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string28 = /.{0,1000}codeLoader\/codeLoader\..{0,1000}/ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string29 = /.{0,1000}cool.{0,1000}\/cool\.zip.{0,1000}/ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string30 = /.{0,1000}coolv0\.1\.exe.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string31 = /.{0,1000}Cooolis.{0,1000}shellcode.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string32 = /.{0,1000}CooolisAdjustTokenPrivileges.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string33 = /.{0,1000}CooolisCreateRemoteThread.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string34 = /.{0,1000}Cooolis\-ExternalC2.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string35 = /.{0,1000}Cooolis\-ms\.exe.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string36 = /.{0,1000}Cooolis\-msf.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string37 = /.{0,1000}Cooolis\-msX64\.zip.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string38 = /.{0,1000}Cooolis\-msX86\.zip.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string39 = /.{0,1000}Cooolis\-Reflective.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string40 = /.{0,1000}Cooolis\-Shellcode.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string41 = /.{0,1000}Cooolis\-String\..{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string42 = /.{0,1000}CooolisVirtualAlloc.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string43 = /.{0,1000}DllExport\s\-.{0,1000}/ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string44 = /.{0,1000}Ed1s0nZ\/cool\/.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string45 = /.{0,1000}execute\-assembly.{0,1000}sigflip.{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string46 = /.{0,1000}g_hookedSleep\..{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string47 = /.{0,1000}GetWhoamiCommand.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string48 = /.{0,1000}IERMTCBpbnRvIHByb2Nlc3MgOiA\=.{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string49 = /.{0,1000}initializeShellcodeFluctuation.{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string50 = /.{0,1000}injectShellcode.{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string51 = /.{0,1000}isShellcodeThread.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string52 = /.{0,1000}LUgsLS1IT1NU.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string53 = /.{0,1000}LVAsLS1QT1JU.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string54 = /.{0,1000}LW8sLS1vcHRpb25z.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string55 = /.{0,1000}LWIsLS1idWNrZXQ\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string56 = /.{0,1000}LWYsLS1maWxl.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string57 = /.{0,1000}LXAsLS1waWQ\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string58 = /.{0,1000}LXAsLS1wYXlsb2Fk.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string59 = /.{0,1000}LXUsLS11cmk\=.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string60 = /.{0,1000}med0x2e\/SigFlip.{0,1000}/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string61 = /.{0,1000}NimShellCodeLoader.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string62 = /.{0,1000}NoPowerShell\.cna.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string63 = /.{0,1000}NoPowerShell\.dll.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string64 = /.{0,1000}nopowershell\.exe.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string65 = /.{0,1000}NoPowerShell\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string66 = /.{0,1000}nps\swhoami.{0,1000}/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string67 = /.{0,1000}OEP_Hiijack_Inject_Load.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string68 = /.{0,1000}Q29iYWx0IFN0cmlrZSBFeHRlcm5hbCBDMiBMb2FkZXI\=.{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string69 = /.{0,1000}readShellcode.{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string70 = /.{0,1000}runShellcode.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string71 = /.{0,1000}Rvn0xsy\/Cooolis\-ms.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string72 = /.{0,1000}RXh0ZXJuYWwgQzIgUG9ydA\=\=.{0,1000}/ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string73 = /.{0,1000}service\/executable\// nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string74 = /.{0,1000}service\/executable\/compile\.exe.{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string75 = /.{0,1000}shellcodeEncryptDecrypt.{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string76 = /.{0,1000}ShellcodeFluctuation\..{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string77 = /.{0,1000}ShellcodeFluctuation64.{0,1000}/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string78 = /.{0,1000}ShellcodeFluctuation86.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string79 = /.{0,1000}sigflip.{0,1000}\/Bof\/.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string80 = /.{0,1000}SigInject\s.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string81 = /.{0,1000}SigLoader\s.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string82 = /.{0,1000}SigLoader\..{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string83 = /.{0,1000}src\\unhook\.c.{0,1000}/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string84 = /.{0,1000}Thread_Hiijack_Inject_Load\..{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string85 = /.{0,1000}ThreadStackSpoofer.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string86 = /.{0,1000}TWV0YXNwbG9pdCBSUEMgTG9hZGVy.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string87 = /.{0,1000}U2hlbGxjb2RlIFBhdGg\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string88 = /.{0,1000}UFR5cGUgQW5kIFBPcHRpb25zIFRvbyBsb25nIQ\=\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string89 = /.{0,1000}UGF5bG9hZCBOYW1lLCBlLmcuIHdpbmRvd3MvbWV0ZXJwcmV0ZXIvcmV2ZXJzZV90Y3A\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string90 = /.{0,1000}UGF5bG9hZCBvcHRpb25zLCBlLmcuIExIT1NUPTEuMS4xLjEsTFBPUlQ9ODg2Ng\=\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string91 = /.{0,1000}UlBDIFNlcnZlciBIb3N0.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string92 = /.{0,1000}UlBDIFNlcnZlciBQb3J0.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string93 = /.{0,1000}UmVmbGVjdGl2ZSBETEwgaW5qZWN0aW9u.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string94 = /.{0,1000}UmVmbGVjdGl2ZSBETEwgT1NTIEJ1Y2tldA\=\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string95 = /.{0,1000}UmVmbGVjdGl2ZSBETEwgUGF0aA\=\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string96 = /.{0,1000}UmVmbGVjdGl2ZSBETEwgVVJJ.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string97 = /.{0,1000}UmVmbGVjdGl2ZSBJbmplY3QgUHJvY2VzcyBJZA\=\=.{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string98 = /.{0,1000}unhook\skernel32.{0,1000}/ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string99 = /.{0,1000}unhook\swldp\samsi.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string100 = /.{0,1000}WypdIENhbid0IENvbm5lY3QgQWxpeXVuIEJ1Y2tldC4\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string101 = /.{0,1000}WypdIFRoZSBCdWNrZXQgb3IgUmVmbGVjdGl2ZSBETEwgVVJJIGlzIEVtcHR5Lg\=\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string102 = /.{0,1000}WytdIEluamVjdGVkIHRoZSA\=.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string103 = /.{0,1000}Y29iYWx0c3RyaWtl.{0,1000}/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string104 = /.{0,1000}YmxvY2s9MTAw.{0,1000}/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string105 = /SigFlip\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
