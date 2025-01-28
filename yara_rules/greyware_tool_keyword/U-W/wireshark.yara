rule wireshark
{
    meta:
        description = "Detection patterns for the tool 'wireshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wireshark"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string1 = "bin/wireshark" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string2 = /dl\.wireshark\.org/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string3 = "dumpcap -" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string4 = "install tshark" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string5 = "libwireshark16" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string6 = "libwireshark-data" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string7 = "libwireshark-dev" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string8 = "libwiretap13" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string9 = "--no-promiscuous-mode" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string10 = "sharkd -a tcp:" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string11 = /tshark\s.{0,1000}\-i\s/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string12 = "tshark -f " nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string13 = "tshark -Q" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string14 = "tshark -r " nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string15 = /tshark.{0,1000}\.deb/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string16 = "Wireshark" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string17 = /wireshark.{0,1000}\.deb/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string18 = /Wireshark.{0,1000}\.dmg/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string19 = /wireshark\-.{0,1000}\.tar\.xz/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string20 = "wireshark-common" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string21 = "wireshark-dev" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string22 = "wireshark-gtk" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string23 = "WiresharkPortable64" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string24 = "wireshark-qt" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string25 = /Wireshark\-win.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
