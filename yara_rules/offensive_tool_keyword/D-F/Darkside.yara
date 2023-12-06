rule Darkside
{
    meta:
        description = "Detection patterns for the tool 'Darkside' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Darkside"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string1 = /\/Darkside\.exe/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string2 = /\/Darkside\.git/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string3 = /\/Darkside\.sln/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string4 = /\\Darkside\.exe/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string5 = /\\Darkside\.sln/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string6 = /D90EFC93\-2F8B\-4427\-B967\-0E78ED45611E/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string7 = /Darkside\.exe\s\-p/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string8 = /Darkside\-master\.zip/ nocase ascii wide
        // Description: C# AV/EDR Killer using less-known driver (BYOVD)
        // Reference: https://github.com/ph4nt0mbyt3/Darkside
        $string9 = /ph4nt0mbyt3\/Darkside/ nocase ascii wide

    condition:
        any of them
}
