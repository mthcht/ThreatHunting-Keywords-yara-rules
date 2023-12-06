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
        $string1 = /Chudry\/Xerror/ nocase ascii wide
        // Description: fully automated pentesting tool
        // Reference: https://github.com/Chudry/Xerror
        $string2 = /cve_2_MSF_exploit_Mapping/ nocase ascii wide
        // Description: fully automated pentesting tool
        // Reference: https://github.com/Chudry/Xerror
        $string3 = /mapper_cve_exploit\.py/ nocase ascii wide
        // Description: fully automated pentesting tool
        // Reference: https://github.com/Chudry/Xerror
        $string4 = /msf_cve_extracter\.py/ nocase ascii wide
        // Description: A BurpSuite plugin intended to help with nuclei template generation.
        // Reference: https://github.com/projectdiscovery/nuclei-burp-plugin
        $string5 = /nuclei\-burp\-plugin/ nocase ascii wide

    condition:
        any of them
}
