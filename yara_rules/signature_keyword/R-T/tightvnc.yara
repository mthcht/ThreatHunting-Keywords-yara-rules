rule tightvnc
{
    meta:
        description = "Detection patterns for the tool 'tightvnc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tightvnc"
        rule_category = "signature_keyword"

    strings:
        // Description: TightVNC is a free and Open Source remote desktop software that lets you access and control a computer over the network - often abused by attackers
        // Reference: https://www.tightvnc.com
        $string1 = "RemoteAccess:Win32/TightVNC" nocase ascii wide

    condition:
        any of them
}
