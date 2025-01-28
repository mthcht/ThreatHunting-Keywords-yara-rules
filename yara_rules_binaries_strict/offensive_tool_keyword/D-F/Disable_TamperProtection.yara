rule Disable_TamperProtection
{
    meta:
        description = "Detection patterns for the tool 'Disable-TamperProtection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Disable-TamperProtection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string1 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string2 = " /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string3 = " /v DisableIOAVProtection /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string4 = " /v DisableOnAccessProtection /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string5 = " /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string6 = /\/Disable\-TamperProtection\.git/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string7 = "/v DisableAntiSpyware /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string8 = /\[\+\]\sWdFilter\sAltitude\sRegistry\skey\shas\sbeen\ssuccessfully\sdeleted/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string9 = /\\Disable\-TamperProtection\\/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string10 = "AlteredSecurity/Disable-TamperProtection" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string11 = "cb0b0fa30345d487f99dce16cb07ef0094938dbf7eedfe48e2a0ad7f2973a7bb" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string12 = /Disable\-TamperProtection\.cpp/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string13 = /Disable\-TamperProtection\.exe/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string14 = "E192C3DF-AE34-4E32-96BA-3D6B56EA76A4" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string15 = /reg\.exe\sadd\s\\\\"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\sDefender\\\\Features\\\\"\s\/v\sTamperProtection\s\/t\sREG_DWORD\s\/d\s4\s\/f/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string16 = /reg\.exe\sdelete\s.{0,100}HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WdFilter\\\\Instances\\\\WdFilter\sInstance.{0,100}\s\/v\sAltitude\s\/f/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string17 = /reg\.exe\sdelete\s.{0,100}HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter\sInstance.{0,100}\s\/v\sAltitude\s\/f/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string18 = "Spawning registry with TrustedInstaller privileges to delete WdFilter " nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string19 = "Spawning registry with TrustedInstaller privileges to Disable 'DisableIOAVProtection' regkey" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string20 = "Spawning registry with TrustedInstaller privileges to Disable 'RealtimeMonitoring' regkey" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string21 = "Spawning registry with TrustedInstaller privileges to Enable 'TamperProtection' regkey" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string22 = /WDFilter\shas\sbeen\ssuccessfully\sunloaded\,\suse\soption\s2\sto\sdisable\sTamper\sProtection\./ nocase ascii wide
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
