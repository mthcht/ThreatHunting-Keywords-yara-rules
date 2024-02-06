rule dnsdumpster
{
    meta:
        description = "Detection patterns for the tool 'dnsdumpster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsdumpster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dns recon & research - find & lookup dns records
        // Reference: https://dnsdumpster.com/
        $string1 = /https\:\/\/dnsdumpster\.com\// nocase ascii wide

    condition:
        any of them
}
