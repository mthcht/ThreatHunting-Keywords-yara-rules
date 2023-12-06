rule SharpSword
{
    meta:
        description = "Detection patterns for the tool 'SharpSword' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string1 = /\/SharpSword\.git/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string2 = /9E357027\-8AA6\-4376\-8146\-F5AF610E14BB/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string3 = /OG\-Sadpanda\/SharpSword/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string4 = /SharpSword\.csproj/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string5 = /SharpSword\.exe/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string6 = /SharpSword\.sln/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string7 = /SharpSword\-main\./ nocase ascii wide

    condition:
        any of them
}
