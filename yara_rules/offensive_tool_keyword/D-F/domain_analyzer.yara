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
        $string1 = /.{0,1000}\scrawler\.py\s\-u\shttp.{0,1000}/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string2 = /.{0,1000}\/crawler\.py\s\-u\shttp.{0,1000}/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string3 = /.{0,1000}\/domain_analyzer\.git.{0,1000}/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string4 = /.{0,1000}\/domain_analyzer:latest.{0,1000}/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string5 = /.{0,1000}domain_analyzer\.py.{0,1000}/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string6 = /.{0,1000}domain_analyzer\-master.{0,1000}/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string7 = /.{0,1000}eldraco\/domain_analyzer.{0,1000}/ nocase ascii wide
        // Description: Analyze the security of any domain by finding all the information possible
        // Reference: https://github.com/eldraco/domain_analyzer
        $string8 = /.{0,1000}verovaleros\/domain_analyzer.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
