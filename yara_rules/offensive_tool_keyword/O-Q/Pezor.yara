rule Pezor
{
    meta:
        description = "Detection patterns for the tool 'Pezor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pezor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string1 = /\s\-64\s\-format\=bof\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string2 = /\s\-64\s\-format\=dll\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string3 = /\s\-64\s\-format\=service\-dll\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string4 = /\s\-fluctuate\=NA\s\-sleep\=/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string5 = /\s\-fluctuate\=RW\s\-sleep\=/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string6 = /\s\-format\=bof\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string7 = /\s\-format\=bof\s\-cleanup\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string8 = /\s\-format\=dotnet\s\-sleep\=/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string9 = /\s\-format\=dotnet\-pinvoke\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string10 = /\s\-format\=dotnet\-pinvoke\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string11 = /\s\-format\=reflective\-dll\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string12 = /\s\-format\=reflective\-dll\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string13 = /\s\-format\=service\-dll\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string14 = /\s\-format\=service\-exe\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string15 = /\skalilinux\/kali\-rolling/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string16 = /\s\-p\s.{0,1000}\\mimi\.out/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string17 = /\sPEzor\.py\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string18 = /\sPEzor\.sh\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string19 = /\sPEzor\.sh\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string20 = /\s\-sgn\s\-syscalls\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string21 = /\s\-sgn\s\-unhook\s\-antidebug\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string22 = /\s\-syscalls\s\-sleep\=.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string23 = /\s\-unhook\s\-antidebug\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string24 = /\s\-unhook\s\-antidebug\s.{0,1000}\s\-self\s\-sleep/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string25 = /\s\-unhook\s\-syscalls\s\-obfuscate\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string26 = /\.\/PEzor\.sh/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string27 = /\.sh\s\-format\=bof\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string28 = /\.sh\s\-format\=service\-dll\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string29 = /\.sh\s\-format\=service\-exe\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string30 = /\.sh\s\-xorkey\=/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string31 = /\/bof\.cpp\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string32 = /\/inject\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string33 = /\/inline_syscall\.git/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string34 = /\/inline_syscall\/include\/in_memory_init\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string35 = /\/PEzor\.cna/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string36 = /\/PEzor\.git/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string37 = /\/PEzor\.git/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string38 = /\/PEzor\.py/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string39 = /\/PEzor\.sh\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string40 = /\/PEzor\/inject\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string41 = /\/ReflectiveDll\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string42 = /\/ReflectiveDLLInjection\// nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string43 = /\/ReflectiveLoader\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string44 = /\/shellcode\.bin\./ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string45 = /\/shellcode\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string46 = /\/system\:SystemBkup\.hiv\s\/sam\:SamBkup\.hiv/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string47 = /\[PEzor\]\scleanup\scomplete/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string48 = /\[PEzor\]\spayload\sfreed/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string49 = /\[PEzor\]\sstarting\sBOF/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string50 = /\\dll\-sideload\\main\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string51 = /\\PEzor\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string52 = /\\PEzor\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string53 = /\\PEzor\\loader\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string54 = /\\shellcode\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string55 = /_prefix_PEzor_/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string56 = /_REFLECTIVEDLLINJECTION_/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string57 = /\-64\s\-format\=reflective\-dll\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string58 = /cannot\sencode\sthe\sshellcode\swhen\sself\-executing\sthe\spayload/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string59 = /Console\.WriteLine.{0,1000}self\sexecuting\sthe\spayload/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string60 = /cowsay\s\-f\sdragon\s\'PEzor\!\!/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string61 = /\-dll\-sideload\=.{0,1000}\.dll/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string62 = /echo\s\'PEzor\!\!/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string63 = /execute_Pezor/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string64 = /execute\-Pezor/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string65 = /\-format\=dotnet\-createsection\s\-sleep/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string66 = /generate_raw_payload/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string67 = /inject_shellcode_self/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string68 = /iwantmore\.pizza\/posts\/PEzor\.html/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string69 = /PEzor\sgenerated\sBeacon\sObject\sFile/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string70 = /PEzor\!\!\sv/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string71 = /PEzor.{0,1000}\/Inject\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string72 = /Pezor.{0,1000}inject\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string73 = /PEzor\.sh\s\-/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string74 = /PEzor\.sh\s.{0,1000}\.bin/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string75 = /PEzor\.sh\s\-32/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string76 = /PEzor\.sh\s\-64/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string77 = /PEzor\/.{0,1000}\/bof\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string78 = /PEzor\/.{0,1000}syscalls\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string79 = /PEzor\\inject\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string80 = /phra\/Pezor/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string81 = /phra\/Pezor\// nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string82 = /ReflectiveDLLInjection\/dll/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string83 = /shellcode\.bin\.donut/ nocase ascii wide

    condition:
        any of them
}
