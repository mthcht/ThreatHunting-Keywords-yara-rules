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
        $string1 = /.{0,1000}\/SharpSword\.git.{0,1000}/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string2 = /.{0,1000}9E357027\-8AA6\-4376\-8146\-F5AF610E14BB.{0,1000}/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string3 = /.{0,1000}OG\-Sadpanda\/SharpSword.{0,1000}/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string4 = /.{0,1000}SharpSword\.csproj.{0,1000}/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string5 = /.{0,1000}SharpSword\.exe.{0,1000}/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string6 = /.{0,1000}SharpSword\.sln.{0,1000}/ nocase ascii wide
        // Description: Read the contents of MS Word Documents using Cobalt Strike's Execute-Assembly
        // Reference: https://github.com/OG-Sadpanda/SharpSword
        $string7 = /.{0,1000}SharpSword\-main\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
