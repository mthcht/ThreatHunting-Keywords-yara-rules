rule SharpView
{
    meta:
        description = "Detection patterns for the tool 'SharpView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string1 = /\.exe\sGet\-DomainController\s\-Domain\s.{0,1000}\s\-Server\s.{0,1000}\s\-Credential\s/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string2 = /\/PowerView\.ps1/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string3 = /\/SharpView\.git/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string4 = /22A156EA\-2623\-45C7\-8E50\-E864D9FC44D3/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string5 = /Args_Invoke_Kerberoast/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string6 = /SharpView\.exe/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string7 = /SharpView\\SharpView/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string8 = /SharpView\-master/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string9 = /tevora\-threat\/SharpView\// nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string10 = /using\sSharpView\.Enums/ nocase ascii wide

    condition:
        any of them
}
