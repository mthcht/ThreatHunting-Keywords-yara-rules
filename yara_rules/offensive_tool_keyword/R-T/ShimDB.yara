rule ShimDB
{
    meta:
        description = "Detection patterns for the tool 'ShimDB' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShimDB"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string1 = /\/sdb\-explorer\.exe/ nocase ascii wide
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string2 = /\/ShimDB\.git/ nocase ascii wide
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string3 = /\\sdb\-explorer\.exe/ nocase ascii wide
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string4 = /\\sdb\-explorer\.sln/ nocase ascii wide
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string5 = /\\ShimDB\\sdb\-explorer/ nocase ascii wide
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string6 = /223279bb628165de88609c81444f4a9bf9aac6f921ea155ac427a47d13b49084/ nocase ascii wide
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string7 = /A1A949A4\-5CE4\-4FCF\-A3B9\-A2290EA46086/ nocase ascii wide
        // Description: Shim database persistence (Fin7 TTP)
        // Reference: https://github.com/jackson5sec/ShimDB
        $string8 = /jackson5sec\/ShimDB/ nocase ascii wide

    condition:
        any of them
}
