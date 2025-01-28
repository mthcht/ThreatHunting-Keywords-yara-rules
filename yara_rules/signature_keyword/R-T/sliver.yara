rule sliver
{
    meta:
        description = "Detection patterns for the tool 'sliver' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sliver"
        rule_category = "signature_keyword"

    strings:
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/gsmith257-cyber/better-sliver
        $string1 = /HackTool\.Win32\.Sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/gsmith257-cyber/better-sliver
        $string2 = /HEUR\:Trojan\.Linux\.Vilers\.a/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/gsmith257-cyber/better-sliver
        $string3 = /Multi\.Trojan\.Sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/gsmith257-cyber/better-sliver
        $string4 = /Unix\.Malware\.Sliver\-/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/gsmith257-cyber/better-sliver
        $string5 = "VirTool:Linux/Sliver" nocase ascii wide

    condition:
        any of them
}
