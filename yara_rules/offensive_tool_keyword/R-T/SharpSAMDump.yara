rule SharpSAMDump
{
    meta:
        description = "Detection patterns for the tool 'SharpSAMDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSAMDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string1 = /\/SharpSAMDump\.git/ nocase ascii wide
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string2 = /\\SharpSAMDump\-main/ nocase ascii wide
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string3 = ">SharpSAMDump<" nocase ascii wide
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string4 = "158c0b33376d319848cffd69f20dc6e2dc93aa66ed71dffd6f0ee3803da70dd2" nocase ascii wide
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string5 = "4FEAB888-F514-4F2E-A4F7-5989A86A69DE" nocase ascii wide
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string6 = "f97334c71892acdc50380141f0c6144363b7a55a1fe5adf01543b2adbd2d7e44" nocase ascii wide
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string7 = "jojonas/SharpSAMDump" nocase ascii wide
        // Description: SAM dumping via the registry in C#/.NET
        // Reference: https://github.com/jojonas/SharpSAMDump
        $string8 = /SharpSAMDump\.exe/ nocase ascii wide

    condition:
        any of them
}
