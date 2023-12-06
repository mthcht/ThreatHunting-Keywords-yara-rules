rule phuip_fpizdam
{
    meta:
        description = "Detection patterns for the tool 'phuip-fpizdam' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phuip-fpizdam"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is an exploit for a bug in php-fpm (CVE-2019-11043). In certain nginx + php-fpm configurations. the bug is possible to trigger from the outside. This means that a web user may get code execution if you have vulnerable config (see below).
        // Reference: https://github.com/neex/phuip-fpizdam
        $string1 = /phuip\-fpizdam/ nocase ascii wide

    condition:
        any of them
}
