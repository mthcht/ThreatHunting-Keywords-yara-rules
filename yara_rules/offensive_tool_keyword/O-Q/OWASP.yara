rule OWASP
{
    meta:
        description = "Detection patterns for the tool 'OWASP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OWASP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: resources and cheat sheet for web attacks techniques
        // Reference: https://github.com/OWASP
        $string1 = "/OWASP" nocase ascii wide

    condition:
        any of them
}
