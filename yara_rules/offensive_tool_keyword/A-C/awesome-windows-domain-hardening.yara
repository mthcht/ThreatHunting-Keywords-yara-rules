rule awesome_windows_domain_hardening
{
    meta:
        description = "Detection patterns for the tool 'awesome-windows-domain-hardening' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-windows-domain-hardening"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A curated list of awesome Security Hardening techniques for Windows with additional links to exploitation tools
        // Reference: https://github.com/PaulSec/awesome-windows-domain-hardening
        $string1 = /awesome\-windows\-domain\-hardening/ nocase ascii wide

    condition:
        any of them
}
