rule Bashfuscator
{
    meta:
        description = "Detection patterns for the tool 'Bashfuscator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bashfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string1 = /.{0,1000}\s\-c\s.{0,1000}\s\-\-choose\-mutators\s.{0,1000}\s\-s\s1.{0,1000}/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string2 = /.{0,1000}\/Bashfuscator.{0,1000}/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string3 = /.{0,1000}bashfuscator\s\-.{0,1000}/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string4 = /.{0,1000}Bashfuscator\sTeam.{0,1000}/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string5 = /.{0,1000}bashfuscator\.py.{0,1000}/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string6 = /.{0,1000}Bashfuscator\-master.{0,1000}/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string7 = /.{0,1000}command_obfuscator\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
