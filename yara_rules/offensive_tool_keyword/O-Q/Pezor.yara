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
        $string1 = /.{0,1000}\s\-64\s\-format\=bof\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string2 = /.{0,1000}\s\-64\s\-format\=dll\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string3 = /.{0,1000}\s\-64\s\-format\=service\-dll\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string4 = /.{0,1000}\s\-fluctuate\=NA\s\-sleep\=.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string5 = /.{0,1000}\s\-fluctuate\=RW\s\-sleep\=.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string6 = /.{0,1000}\s\-format\=bof\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string7 = /.{0,1000}\s\-format\=bof\s\-cleanup\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string8 = /.{0,1000}\s\-format\=dotnet\s\-sleep\=.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string9 = /.{0,1000}\s\-format\=dotnet\-pinvoke\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string10 = /.{0,1000}\s\-format\=reflective\-dll\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string11 = /.{0,1000}\s\-format\=service\-dll\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string12 = /.{0,1000}\s\-format\=service\-exe\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string13 = /.{0,1000}\skalilinux\/kali\-rolling.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string14 = /.{0,1000}\s\-p\s.{0,1000}\\mimi\.out.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string15 = /.{0,1000}\sPEzor\.sh\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string16 = /.{0,1000}\s\-sgn\s\-syscalls\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string17 = /.{0,1000}\s\-sgn\s\-unhook\s\-antidebug\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string18 = /.{0,1000}\s\-syscalls\s\-sleep\=.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string19 = /.{0,1000}\s\-unhook\s\-antidebug\s.{0,1000}\s\-self\s\-sleep.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string20 = /.{0,1000}\s\-unhook\s\-syscalls\s\-obfuscate\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string21 = /.{0,1000}\/bof\.cpp\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string22 = /.{0,1000}\/inject\.cpp.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string23 = /.{0,1000}\/inline_syscall\.git.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string24 = /.{0,1000}\/inline_syscall\/include\/in_memory_init\.hpp.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string25 = /.{0,1000}\/PEzor\.cna.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string26 = /.{0,1000}\/PEzor\.git.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string27 = /.{0,1000}\/PEzor\.sh\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string28 = /.{0,1000}\/PEzor\/inject\.cpp.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string29 = /.{0,1000}\/ReflectiveDll\.c.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string30 = /.{0,1000}\/ReflectiveDLLInjection\/.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string31 = /.{0,1000}\/ReflectiveLoader\.c.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string32 = /.{0,1000}\/shellcode\.bin\..{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string33 = /.{0,1000}\/shellcode\.hpp.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string34 = /.{0,1000}_prefix_PEzor_.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string35 = /.{0,1000}\-64\s\-format\=reflective\-dll\s.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string36 = /.{0,1000}cowsay\s\-f\sdragon\s\'PEzor\!\!.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string37 = /.{0,1000}echo\s\'PEzor\!\!.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string38 = /.{0,1000}execute_Pezor.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string39 = /.{0,1000}execute\-Pezor.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string40 = /.{0,1000}\-format\=dotnet\-createsection\s\-sleep.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string41 = /.{0,1000}generate_raw_payload.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string42 = /.{0,1000}inject_shellcode_self.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string43 = /.{0,1000}PEzor\sgenerated\sBeacon\sObject\sFile.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string44 = /.{0,1000}PEzor.{0,1000}\/Inject\.c.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string45 = /.{0,1000}Pezor.{0,1000}inject\.hpp.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string46 = /.{0,1000}PEzor\.sh\s\-.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string47 = /.{0,1000}PEzor\.sh\s.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string48 = /.{0,1000}PEzor\/.{0,1000}\/bof\.cpp.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string49 = /.{0,1000}PEzor\/.{0,1000}syscalls\.hpp.{0,1000}/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string50 = /.{0,1000}phra\/Pezor\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
