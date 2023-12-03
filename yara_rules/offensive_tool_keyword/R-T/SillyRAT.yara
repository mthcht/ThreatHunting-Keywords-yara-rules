rule SillyRAT
{
    meta:
        description = "Detection patterns for the tool 'SillyRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SillyRAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Cross Platform multifunctional (Windows/Linux/Mac) RAT.
        // Reference: https://github.com/hash3liZer/SillyRAT
        $string1 = /.{0,1000}hash3liZer\/SillyRAT.{0,1000}/ nocase ascii wide
        // Description: A Cross Platform multifunctional (Windows/Linux/Mac) RAT.
        // Reference: https://github.com/hash3liZer/SillyRAT
        $string2 = /.{0,1000}keylogger\sdump.{0,1000}/ nocase ascii wide
        // Description: A Cross Platform multifunctional (Windows/Linux/Mac) RAT.
        // Reference: https://github.com/hash3liZer/SillyRAT
        $string3 = /.{0,1000}server\.py\sgenerate\s\-\-address\s.{0,1000}\s\-\-port\s.{0,1000}\s\-\-output\s.{0,1000}\s\-\-source.{0,1000}/ nocase ascii wide
        // Description: A Cross Platform multifunctional (Windows/Linux/Mac) RAT.
        // Reference: https://github.com/hash3liZer/SillyRAT
        $string4 = /.{0,1000}SillyRAT\.git.{0,1000}/ nocase ascii wide
        // Description: A Cross Platform multifunctional (Windows/Linux/Mac) RAT.
        // Reference: https://github.com/hash3liZer/SillyRAT
        $string5 = /.{0,1000}sillyrat\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
