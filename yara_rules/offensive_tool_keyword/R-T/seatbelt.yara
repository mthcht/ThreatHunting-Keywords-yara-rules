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
        $string1 = /\s\-\-Args\sAntiVirus\s\-\-XorKey/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string2 = /\s\-\-args\swhoami/ nocase ascii wide
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
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string15 = /\/Seatbelt\.git/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string16 = /\/Seatbelt\/Commands/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string17 = /\\Seatbelt\.sln/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string18 = /\\Seatbelt\\Commands\\/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string19 = /\\Seatbelt\\Program\.cs/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string20 = /\\Seatbelt\\Seatbelt\.cs/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string21 = /26edf5820094951dd18e20e86b1151d7113f1e17b64f1d3817d4995885559850/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string22 = /ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string23 = /AEC32155\-D589\-4150\-8FE7\-2900DF4554C8/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string24 = /\-\-assemblyargs\sAntiVirus\sAppLocker/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string25 = /GhostPack\/Seatbelt/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string26 = /Invoke\-WCMDump\.ps1/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string27 = /Seatbelt.{0,1000}\s\-group\=all/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string28 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string29 = /SeatbeltNet.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
