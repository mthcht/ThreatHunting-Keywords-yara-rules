rule amass
{
    meta:
        description = "Detection patterns for the tool 'amass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "amass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string1 = /.{0,1000}OWASP.{0,1000}Amass.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
