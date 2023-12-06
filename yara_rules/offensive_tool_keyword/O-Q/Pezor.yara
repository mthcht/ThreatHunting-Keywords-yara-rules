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
        $string10 = /\s\-format\=reflective\-dll\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string11 = /\s\-format\=service\-dll\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string12 = /\s\-format\=service\-exe\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string13 = /\skalilinux\/kali\-rolling/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string14 = /\s\-p\s.{0,1000}\\mimi\.out/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string15 = /\sPEzor\.sh\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string16 = /\s\-sgn\s\-syscalls\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string17 = /\s\-sgn\s\-unhook\s\-antidebug\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string18 = /\s\-syscalls\s\-sleep\=.{0,1000}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string19 = /\s\-unhook\s\-antidebug\s.{0,1000}\s\-self\s\-sleep/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string20 = /\s\-unhook\s\-syscalls\s\-obfuscate\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string21 = /\/bof\.cpp\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string22 = /\/inject\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string23 = /\/inline_syscall\.git/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string24 = /\/inline_syscall\/include\/in_memory_init\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string25 = /\/PEzor\.cna/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string26 = /\/PEzor\.git/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string27 = /\/PEzor\.sh\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string28 = /\/PEzor\/inject\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string29 = /\/ReflectiveDll\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string30 = /\/ReflectiveDLLInjection\// nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string31 = /\/ReflectiveLoader\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string32 = /\/shellcode\.bin\./ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string33 = /\/shellcode\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string34 = /_prefix_PEzor_/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string35 = /\-64\s\-format\=reflective\-dll\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string36 = /cowsay\s\-f\sdragon\s\'PEzor\!\!/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string37 = /echo\s\'PEzor\!\!/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string38 = /execute_Pezor/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string39 = /execute\-Pezor/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string40 = /\-format\=dotnet\-createsection\s\-sleep/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string41 = /generate_raw_payload/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string42 = /inject_shellcode_self/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string43 = /PEzor\sgenerated\sBeacon\sObject\sFile/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string44 = /PEzor.{0,1000}\/Inject\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string45 = /Pezor.{0,1000}inject\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string46 = /PEzor\.sh\s\-/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string47 = /PEzor\.sh\s.{0,1000}\.bin/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string48 = /PEzor\/.{0,1000}\/bof\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string49 = /PEzor\/.{0,1000}syscalls\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string50 = /phra\/Pezor\// nocase ascii wide

    condition:
        any of them
}
