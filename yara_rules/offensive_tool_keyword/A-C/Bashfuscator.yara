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
        $string1 = /\s\-c\s.{0,1000}\s\-\-choose\-mutators\s.{0,1000}\s\-s\s1/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string2 = /\/Bashfuscator/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string3 = /bashfuscator\s\-/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string4 = /Bashfuscator\sTeam/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string5 = /bashfuscator\.py/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string6 = /Bashfuscator\-master/ nocase ascii wide
        // Description: A fully configurable and extendable Bash obfuscation framework
        // Reference: https://github.com/Bashfuscator/Bashfuscator
        $string7 = /command_obfuscator\.py/ nocase ascii wide

    condition:
        any of them
}
