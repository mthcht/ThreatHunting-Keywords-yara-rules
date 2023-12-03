rule Xerror
{
    meta:
        description = "Detection patterns for the tool 'Xerror' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xerror"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: fully automated pentesting tool
        // Reference: https://github.com/Chudry/Xerror
        $string1 = /.{0,1000}Chudry\/Xerror.{0,1000}/ nocase ascii wide
        // Description: fully automated pentesting tool
        // Reference: https://github.com/Chudry/Xerror
        $string2 = /.{0,1000}cve_2_MSF_exploit_Mapping.{0,1000}/ nocase ascii wide
        // Description: fully automated pentesting tool
        // Reference: https://github.com/Chudry/Xerror
        $string3 = /.{0,1000}mapper_cve_exploit\.py.{0,1000}/ nocase ascii wide
        // Description: fully automated pentesting tool
        // Reference: https://github.com/Chudry/Xerror
        $string4 = /.{0,1000}msf_cve_extracter\.py.{0,1000}/ nocase ascii wide
        // Description: A BurpSuite plugin intended to help with nuclei template generation.
        // Reference: https://github.com/projectdiscovery/nuclei-burp-plugin
        $string5 = /.{0,1000}nuclei\-burp\-plugin.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
