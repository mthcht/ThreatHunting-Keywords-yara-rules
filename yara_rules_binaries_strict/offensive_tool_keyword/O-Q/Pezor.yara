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
        $string1 = " -64 -format=bof " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string2 = " -64 -format=dll " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string3 = " -64 -format=service-dll " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string4 = " -fluctuate=NA -sleep=" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string5 = " -fluctuate=RW -sleep=" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string6 = /\s\-format\=bof\s.{0,100}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string7 = " -format=bof -cleanup " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string8 = " -format=dotnet -sleep=" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string9 = " -format=dotnet-pinvoke " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string10 = /\s\-format\=dotnet\-pinvoke\s.{0,100}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string11 = " -format=reflective-dll " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string12 = /\s\-format\=reflective\-dll\s.{0,100}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string13 = /\s\-format\=service\-dll\s.{0,100}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string14 = /\s\-format\=service\-exe\s.{0,100}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string15 = " kalilinux/kali-rolling"
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string16 = /\s\-p\s.{0,100}\\mimi\.out/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string17 = /\sPEzor\.py\s/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string18 = /\sPEzor\.sh\s/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string19 = /\sPEzor\.sh\s/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string20 = " -sgn -syscalls " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string21 = " -sgn -unhook -antidebug " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string22 = /\s\-syscalls\s\-sleep\=.{0,100}\.exe/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string23 = " -unhook -antidebug " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string24 = /\s\-unhook\s\-antidebug\s.{0,100}\s\-self\s\-sleep/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string25 = " -unhook -syscalls -obfuscate " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string26 = /\.\/PEzor\.sh/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string27 = /\.sh\s\-format\=bof\s.{0,100}\.exe/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string28 = /\.sh\s\-format\=service\-dll\s/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string29 = /\.sh\s\-format\=service\-exe\s/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string30 = /\.sh\s\-xorkey\=/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string31 = /\/bof\.cpp\s/
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
        $string38 = /\/PEzor\.py/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string39 = /\/PEzor\.sh\s/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string40 = /\/PEzor\/inject\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string41 = /\/ReflectiveDll\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string42 = "/ReflectiveDLLInjection/" nocase ascii wide
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
        $string46 = /\/system\:SystemBkup\.hiv\s\/sam\:SamBkup\.hiv/
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
        $string55 = "_prefix_PEzor_" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string56 = "_REFLECTIVEDLLINJECTION_" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string57 = "-64 -format=reflective-dll " nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string58 = "cannot encode the shellcode when self-executing the payload" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string59 = /Console\.WriteLine.{0,100}self\sexecuting\sthe\spayload/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string60 = "cowsay -f dragon 'PEzor!!" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string61 = /\-dll\-sideload\=.{0,100}\.dll/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string62 = "echo 'PEzor!!" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string63 = "execute_Pezor" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string64 = "execute-Pezor" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string65 = "-format=dotnet-createsection -sleep" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string66 = "generate_raw_payload" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string67 = "inject_shellcode_self" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string68 = /iwantmore\.pizza\/posts\/PEzor\.html/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string69 = "PEzor generated Beacon Object File" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string70 = "PEzor!! v" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string71 = /PEzor.{0,100}\/Inject\.c/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string72 = /Pezor.{0,100}inject\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string73 = /PEzor\.sh\s\-/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string74 = /PEzor\.sh\s.{0,100}\.bin/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string75 = /PEzor\.sh\s\-32/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string76 = /PEzor\.sh\s\-64/
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string77 = /PEzor\/.{0,100}\/bof\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string78 = /PEzor\/.{0,100}syscalls\.hpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string79 = /PEzor\\inject\.cpp/ nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string80 = "phra/Pezor" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string81 = "phra/Pezor/" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string82 = "ReflectiveDLLInjection/dll" nocase ascii wide
        // Description: Open-Source Shellcode & PE Packer
        // Reference: https://github.com/phra/PEzor
        $string83 = /shellcode\.bin\.donut/ nocase ascii wide
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
