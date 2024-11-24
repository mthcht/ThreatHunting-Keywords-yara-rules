rule SharpDoor
{
    meta:
        description = "Detection patterns for the tool 'SharpDoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string1 = /\sSharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string2 = /\sSharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string3 = /\/SharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string4 = /\/SharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string5 = /\/SharpDoor\.git/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string6 = /\/SharpDoor\.git/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string7 = /\[\!\]\sUnhandled\sSharpDoor\sexception/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string8 = /\\SharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string9 = /\\SharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string10 = /\\termsrv\.patch\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string11 = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string12 = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string13 = /\\Users\\Public\\termsrv\.patch\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string14 = "4cec28b4c00002245dffc8346be0cc11" nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string15 = /Allow\sMultiple\sRDP\s\(Remote\sDesktop\)\sSessions\sBy\sPatching\stermsrv\.dll\sFile/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string16 = "infosecn1nja/SharpDoor" nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string17 = "infosecn1nja/SharpDoor" nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string18 = /SharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string19 = "SharpDoor-master" nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string20 = "SharpDoor-master" nocase ascii wide
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
