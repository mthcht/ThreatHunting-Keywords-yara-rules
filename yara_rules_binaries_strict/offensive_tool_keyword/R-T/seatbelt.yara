rule seatbelt
{
    meta:
        description = "Detection patterns for the tool 'seatbelt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "seatbelt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string1 = " --Args AntiVirus --XorKey" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string2 = " --args whoami" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string3 = /\.exe\s\s\-group\=remote\s\-computername\=/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string4 = /\.exe\s\-group\=all\s/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string5 = /\.exe\s\-group\=all\s\-AuditPolicies/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string6 = /\.exe\s\-group\=all\s\-full/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string7 = /\.exe\s\-group\=remote\s/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string8 = /\.exe\s\-group\=system\s/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string9 = /\.exe\s\-group\=user\s/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string10 = /\.exe\sNonstandardProcesses/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string11 = /\.exe\sNTLMSettings/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string12 = /\.exe\s\-q\sInterestingProcesses/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string13 = /\.exe\s\-q\sPowerShell/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string14 = /\.exe\s\-q\sWindowsDefender/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string15 = /\/Seatbelt\.exe/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string16 = /\/Seatbelt\.git/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string17 = "/Seatbelt/Commands" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string18 = /\\Seatbelt\.exe/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string19 = /\\Seatbelt\.sln/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string20 = /\\Seatbelt\\Commands\\/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string21 = /\\Seatbelt\\Program\.cs/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string22 = /\\Seatbelt\\Seatbelt\.cs/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string23 = ">Seatbelt<" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string24 = "0dece401c686c54a06aba232c7bf4f80b49e4087aed13078c4721676341db992" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string25 = "0fa3195520e1b55fa7d36818a916b9b8cee1ee673997ec71c18a52947697d2fb" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string26 = "26edf5820094951dd18e20e86b1151d7113f1e17b64f1d3817d4995885559850" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string27 = /ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string28 = "AEC32155-D589-4150-8FE7-2900DF4554C8" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string29 = "--assemblyargs AntiVirus AppLocker" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string30 = "b31fc5e7f730a95d7cfc83476e543e00f94bae8f3635101c4b991f0d664ac0d2" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string31 = "GhostPack/Seatbelt" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string32 = /Invoke\-WCMDump\.ps1/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string33 = /Seatbelt.{0,100}\s\-group\=all/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string34 = /Seatbelt\.Commands\.Windows/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string35 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string36 = /SeatbeltNet.{0,100}\.exe/ nocase ascii wide
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
