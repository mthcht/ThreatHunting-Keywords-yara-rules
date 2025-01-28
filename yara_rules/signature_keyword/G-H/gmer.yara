rule gmer
{
    meta:
        description = "Detection patterns for the tool 'gmer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gmer"
        rule_category = "signature_keyword"

    strings:
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string1 = "HackTool:Win32/Gmer" nocase ascii wide

    condition:
        any of them
}
