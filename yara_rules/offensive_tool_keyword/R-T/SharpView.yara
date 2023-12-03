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
        $string1 = /.{0,1000}\.exe\sGet\-DomainController\s\-Domain\s.{0,1000}\s\-Server\s.{0,1000}\s\-Credential\s.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string2 = /.{0,1000}\/PowerView\.ps1.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string3 = /.{0,1000}\/SharpView\.git.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string4 = /.{0,1000}22A156EA\-2623\-45C7\-8E50\-E864D9FC44D3.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string5 = /.{0,1000}Args_Invoke_Kerberoast.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string6 = /.{0,1000}SharpView\.exe.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string7 = /.{0,1000}SharpView\\SharpView.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string8 = /.{0,1000}SharpView\-master.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string9 = /.{0,1000}tevora\-threat\/SharpView\/.{0,1000}/ nocase ascii wide
        // Description: C# implementation of harmj0y's PowerView
        // Reference: https://github.com/tevora-threat/SharpView/
        $string10 = /.{0,1000}using\sSharpView\.Enums.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
