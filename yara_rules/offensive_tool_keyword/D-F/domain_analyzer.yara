rule domain_analyzer
{
    meta:
        description = "Detection patterns for the tool 'domain_analyzer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domain_analyzer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string1 = /\scrawler\.py\s\-u\shttp/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string2 = /\/crawler\.py\s\-u\shttp/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string3 = /\/domain_analyzer\.git/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string4 = /\/domain_analyzer\:latest/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string5 = /domain_analyzer\.py/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string6 = /domain_analyzer\-master/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string7 = /eldraco\/domain_analyzer/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string8 = /verovaleros\/domain_analyzer/ nocase ascii wide

    condition:
        any of them
}
