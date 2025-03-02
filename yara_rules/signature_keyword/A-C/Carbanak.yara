rule Carbanak
{
    meta:
        description = "Detection patterns for the tool 'Carbanak' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Carbanak"
        rule_category = "signature_keyword"

    strings:
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string1 = /Backdoor\.Win32\.CARBANAK\.A/ nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string2 = "Troj/Carbanak-" nocase ascii wide
        // Description: remote backdoor used by a group of the same name (Carbanak). It is intended for espionage - data exfiltration and providing remote access to infected machines
        // Reference: https://github.com/0x25bit/Updated-Carbanak-Source-with-Plugins
        $string3 = /Trojan\.Carberp\.B\!g1/ nocase ascii wide

    condition:
        any of them
}
