rule MDE_Enum
{
    meta:
        description = "Detection patterns for the tool 'MDE_Enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MDE_Enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string1 = /\/MDE_Enum\.git/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string2 = /\[\+\]\sEnumerating\sASR\sRules\son\sLocal\sSystem/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string3 = /\[\+\]\sEnumerating\sASR\sRules\son\sRemote\sSystem\s/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string4 = /\\MDE_Enum\.csproj/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string5 = /\\MDE_Enum\.exe/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string6 = /\\MDE_Enum\\Program\.cs/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string7 = ">MDE_Enum<" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string8 = "0xsp-SRD/MDE_Enum" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string9 = "5EC16C3F-1E62-4661-8C20-504CB0E55441" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string10 = "65cf6179c85728317f11460314779b365ba77199352a2b11624729f788daf6bc" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string11 = "7b39a858a51efa5160d65300b9b89695caf33ec380f69a40cdb7f742e8f05a46" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string12 = "MDE_Enum /local /asr" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string13 = "MDE_Enum /local /paths" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string14 = /ObjectQuery\(\\"SELECT\s.{0,100}\sFROM\sMSFT_MpPreference\\"\)/ nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string15 = "Remote System - MDE_Enum " nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string16 = "-Retrieve Defender ASR Triggered Events -" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string17 = "-Retrieve Defender Exclusion Paths Using Event Logs -" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string18 = "using MDE_Enum;" nocase ascii wide
        // Description: extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules
        // Reference: https://github.com/0xsp-SRD/MDE_Enum
        $string19 = "WindowsDefenderEventLog_Enum " nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
