rule XSS_Payloads
{
    meta:
        description = "Detection patterns for the tool 'XSS-Payloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "XSS-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fine collection of selected javascript payloads.
        // Reference: http://www.xss-payloads.com/
        $string1 = /XSS\-Payloads/ nocase ascii wide

    condition:
        any of them
}
