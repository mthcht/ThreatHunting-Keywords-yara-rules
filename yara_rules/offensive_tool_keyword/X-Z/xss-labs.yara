rule xss_labs
{
    meta:
        description = "Detection patterns for the tool 'xss-labs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xss-labs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: small set of PHP scripts to practice exploiting XSS and CSRF injection vulns
        // Reference: https://github.com/paralax/xss-labs
        $string1 = /XSS\-labs/ nocase ascii wide

    condition:
        any of them
}
