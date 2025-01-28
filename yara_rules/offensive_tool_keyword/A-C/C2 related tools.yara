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
        $string1 = /\sbeacon64\.bin\s/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string2 = /\sNoPowerShell\./ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string3 = /\s\-pe\-exp\-list\s.{0,1000}\.dll/ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string4 = /\ssigflip\./ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string5 = " -U msf -P msf " nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string6 = /\!wPkgPath\!.{0,1000}\!ak\!/ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string7 = "/bypass_mod/loader" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string8 = "/Cooolis-ms/" nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string9 = /\/DllExport\.bat/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string10 = "/nopowershell/" nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string11 = "/ShellcodeFluctuation" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string12 = /\/SigFlip\./ nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string13 = "/SigFlip/" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string14 = "/SigLoader/" nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string15 = "/unhook-bof" nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string16 = /\\codeloader\.exe/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string17 = /\\Cooolis\-ms\-Loader\\/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string18 = /\\DllExport\.bat/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string19 = /\\NoPowerShell\./ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string20 = /\\tests\\beacon64\.bin/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string21 = /APC_Ijnect_Load\.nim/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string22 = /BOFNET\.dll/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string23 = /bofnet_execute\./ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string24 = "bWV0YXNwbG9pdA==" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string25 = "c2hlbGxjb2Rl" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string26 = "cGlwZW5hbWU9" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string27 = "cmVmbGVjdGl2ZQ==" nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string28 = /codeLoader\/codeLoader\./ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string29 = /cool.{0,1000}\/cool\.zip/ nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string30 = /coolv0\.1\.exe/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string31 = /Cooolis.{0,1000}shellcode/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string32 = "CooolisAdjustTokenPrivileges" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string33 = "CooolisCreateRemoteThread" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string34 = "Cooolis-ExternalC2" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string35 = /Cooolis\-ms\.exe/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string36 = "Cooolis-msf" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string37 = /Cooolis\-msX64\.zip/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string38 = /Cooolis\-msX86\.zip/ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string39 = "Cooolis-Reflective" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string40 = "Cooolis-Shellcode" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string41 = /Cooolis\-String\./ nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string42 = "CooolisVirtualAlloc" nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string43 = "DllExport -" nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string44 = "Ed1s0nZ/cool/" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string45 = /execute\-assembly.{0,1000}sigflip/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string46 = /g_hookedSleep\./ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string47 = "GetWhoamiCommand" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string48 = "IERMTCBpbnRvIHByb2Nlc3MgOiA=" nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string49 = "initializeShellcodeFluctuation" nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string50 = "injectShellcode" nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string51 = "isShellcodeThread" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string52 = "LUgsLS1IT1NU" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string53 = "LVAsLS1QT1JU" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string54 = "LW8sLS1vcHRpb25z" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string55 = "LWIsLS1idWNrZXQ=" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string56 = "LWYsLS1maWxl" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string57 = "LXAsLS1waWQ=" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string58 = "LXAsLS1wYXlsb2Fk" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string59 = "LXUsLS11cmk=" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string60 = "med0x2e/SigFlip" nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string61 = "NimShellCodeLoader" nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string62 = /NoPowerShell\.cna/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string63 = /NoPowerShell\.dll/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string64 = /nopowershell\.exe/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string65 = /NoPowerShell\/.{0,1000}\.cs/ nocase ascii wide
        // Description: PowerShell rebuilt in C# for Red Teaming purposes
        // Reference: https://github.com/bitsadmin/nopowershell
        $string66 = "nps whoami" nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string67 = "OEP_Hiijack_Inject_Load" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string68 = "Q29iYWx0IFN0cmlrZSBFeHRlcm5hbCBDMiBMb2FkZXI=" nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string69 = "readShellcode" nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string70 = "runShellcode" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string71 = "Rvn0xsy/Cooolis-ms" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string72 = "RXh0ZXJuYWwgQzIgUG9ydA==" nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string73 = "service/executable/" nocase ascii wide
        // Description: An anti-virus platform written in the Golang-Gin framework with built-in BypassAV methods such as separation and bundling.
        // Reference: https://github.com/Ed1s0nZ/cool
        $string74 = /service\/executable\/compile\.exe/ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string75 = "shellcodeEncryptDecrypt" nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string76 = /ShellcodeFluctuation\./ nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string77 = "ShellcodeFluctuation64" nocase ascii wide
        // Description: An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents
        // Reference: https://github.com/mgeeky/ShellcodeFluctuation
        $string78 = "ShellcodeFluctuation86" nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string79 = /sigflip.{0,1000}\/Bof\// nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string80 = "SigInject " nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string81 = "SigLoader " nocase ascii wide
        // Description: SigFlip is a tool for patching authenticode signed PE files (exe. dll. sys ..etc) without invalidating or breaking the existing signature.
        // Reference: https://github.com/med0x2e/SigFlip
        $string82 = /SigLoader\./ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string83 = /src\\unhook\.c/ nocase ascii wide
        // Description: A shellcode loader written using nim
        // Reference: https://github.com/aeverj/NimShellCodeLoader
        $string84 = /Thread_Hiijack_Inject_Load\./ nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string85 = "ThreadStackSpoofer" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string86 = "TWV0YXNwbG9pdCBSUEMgTG9hZGVy" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string87 = "U2hlbGxjb2RlIFBhdGg=" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string88 = "UFR5cGUgQW5kIFBPcHRpb25zIFRvbyBsb25nIQ==" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string89 = "UGF5bG9hZCBOYW1lLCBlLmcuIHdpbmRvd3MvbWV0ZXJwcmV0ZXIvcmV2ZXJzZV90Y3A=" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string90 = "UGF5bG9hZCBvcHRpb25zLCBlLmcuIExIT1NUPTEuMS4xLjEsTFBPUlQ9ODg2Ng==" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string91 = "UlBDIFNlcnZlciBIb3N0" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string92 = "UlBDIFNlcnZlciBQb3J0" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string93 = "UmVmbGVjdGl2ZSBETEwgaW5qZWN0aW9u" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string94 = "UmVmbGVjdGl2ZSBETEwgT1NTIEJ1Y2tldA==" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string95 = "UmVmbGVjdGl2ZSBETEwgUGF0aA==" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string96 = "UmVmbGVjdGl2ZSBETEwgVVJJ" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string97 = "UmVmbGVjdGl2ZSBJbmplY3QgUHJvY2VzcyBJZA==" nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string98 = "unhook kernel32" nocase ascii wide
        // Description: Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.
        // Reference: https://github.com/mgeeky/ThreadStackSpoofer
        $string99 = "unhook wldp amsi" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string100 = "WypdIENhbid0IENvbm5lY3QgQWxpeXVuIEJ1Y2tldC4=" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string101 = "WypdIFRoZSBCdWNrZXQgb3IgUmVmbGVjdGl2ZSBETEwgVVJJIGlzIEVtcHR5Lg==" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string102 = "WytdIEluamVjdGVkIHRoZSA=" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string103 = "Y29iYWx0c3RyaWtl" nocase ascii wide
        // Description: Cooolis-ms is a code execution tool that includes Metasploit Payload Loader. Cobalt Strike External C2 Loader. and Reflective DLL injection. Its positioning is to avoid some codes that we will execute and contain characteristics in static killing. and help red team personnel It is more convenient and quick to switch from the Web container environment to the C2 environment for further work.
        // Reference: https://github.com/Rvn0xsy/Cooolis-ms
        $string104 = "YmxvY2s9MTAw" nocase ascii wide

    condition:
        any of them
}
