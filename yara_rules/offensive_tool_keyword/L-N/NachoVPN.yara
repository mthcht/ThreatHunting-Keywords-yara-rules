rule NachoVPN
{
    meta:
        description = "Detection patterns for the tool 'NachoVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NachoVPN"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string1 = " localgroup administrators pwnd /add" nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string2 = /\snachovpn\.server/ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string3 = " nachovpn:latest " nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string4 = " --rm -it nachovpn" nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string5 = " user pwnd Passw0rd123!" nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string6 = /\/NachoVPN\.git/ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string7 = "/nachovpn:release" nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string8 = /\/nachovpn\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string9 = "AmberWolfCyber/NachoVPN" nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string10 = /connect\.nachovpn\.local/ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string11 = /nachovpn\.core\./ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string12 = /nachovpn\.local/ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string13 = /nachovpn\.plugins\./ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string14 = /nachovpn\/server\.py/ nocase ascii wide
        // Description: NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients using a rogue VPN serve
        // Reference: https://github.com/AmberWolfCyber/NachoVPN
        $string15 = "touch /tmp/pwnd"

    condition:
        any of them
}
