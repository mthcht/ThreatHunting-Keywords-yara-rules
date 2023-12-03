rule WAF_bypass_Cheat_Sheet
{
    meta:
        description = "Detection patterns for the tool 'WAF-bypass-Cheat-Sheet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WAF-bypass-Cheat-Sheet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WAF/IPS/DLP bypass Cheat Sheet
        // Reference: https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet
        $string1 = /.{0,1000}WAF\-bypass\-Cheat\-Sheet.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
