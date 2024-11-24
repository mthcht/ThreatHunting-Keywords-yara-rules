rule seatbelt
{
    meta:
        description = "Detection patterns for the tool 'seatbelt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "seatbelt"
        rule_category = "signature_keyword"

    strings:
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string1 = "ATK/Seatbelt-A" nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string2 = /HackTool\.MSIL\.Seatbelt/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string3 = /Hacktool\.Seatbelt/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string4 = /Win\.Packed\.Seatbelt\-/ nocase ascii wide
        // Description: Seatbelt is a comprehensive security scanning tool that can be used to perform a variety of checks. including but not limited to. user privileges. logged in users. network information. system information. and many others
        // Reference: https://github.com/GhostPack/Seatbelt
        $string5 = /Windows\.Hacktool\.Seatbelt/ nocase ascii wide

    condition:
        any of them
}
