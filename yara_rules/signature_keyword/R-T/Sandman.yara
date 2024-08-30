rule Sandman
{
    meta:
        description = "Detection patterns for the tool 'Sandman' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sandman"
        rule_category = "signature_keyword"

    strings:
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string1 = /ATK\/Sandman\-A/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string2 = /Backdoor\.MSIL\.Sandman/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string3 = /VirTool\:MSIL\/Sabakz\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}
