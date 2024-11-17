rule WMImplant
{
    meta:
        description = "Detection patterns for the tool 'WMImplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMImplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string1 = /\s\-Remote_Posh\s\-Location\s.{0,100}\.ps1\s\-Function\sInvoke\-.{0,100}\s\-ComputerName\s/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string2 = /Edit\-FileWMI/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string3 = /Find\-FileWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string4 = /Find\-VacantComputer/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string5 = /Get\-FileContentsWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string6 = /Get\-WMIEventLogins/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string7 = /Invoke\-FileTransferWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string8 = /Invoke\-LSWMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string9 = /Invoke\-PowerOptionsWMI/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string10 = /Invoke\-ProcessPunisher/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string11 = /Invoke\-ProcSpawn\s\-Command\s/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string12 = /Invoke\-ProcSpawn/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string13 = /Invoke\-RemoteScriptWithOutput/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string14 = /Invoke\-WMImplant/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string15 = /Invoke\-WMIObfuscatedPSCommand/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string16 = /powershell\.exe\s\-command\s.{0,100}Enable\-PSRemoting\s\-Force.{0,100}\s\-ComputerName\s/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string17 = /Show\-WMImplantMainMenu/ nocase ascii wide
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string18 = /WMImplant/ nocase ascii wide
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
