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
        $string1 = /.{0,1000}dl\.wireshark\.org.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string2 = /.{0,1000}dumpcap\s\-.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string3 = /.{0,1000}install\stshark.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string4 = /.{0,1000}libwireshark16.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string5 = /.{0,1000}libwireshark\-data.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string6 = /.{0,1000}libwireshark\-dev.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string7 = /.{0,1000}libwiretap13.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string8 = /.{0,1000}\-\-no\-promiscuous\-mode.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string9 = /.{0,1000}sharkd\s\-a\stcp:.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string10 = /.{0,1000}tshark\s.{0,1000}\-i\s.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string11 = /.{0,1000}tshark\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string12 = /.{0,1000}tshark\s\-Q.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string13 = /.{0,1000}tshark\s\-r\s.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string14 = /.{0,1000}tshark.{0,1000}\.deb.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string15 = /.{0,1000}Wireshark.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string16 = /.{0,1000}wireshark.{0,1000}\.deb.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string17 = /.{0,1000}Wireshark.{0,1000}\.dmg.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string18 = /.{0,1000}wireshark\-.{0,1000}\.tar\.xz.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string19 = /.{0,1000}wireshark\-common.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string20 = /.{0,1000}wireshark\-dev.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string21 = /.{0,1000}wireshark\-gtk.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string22 = /.{0,1000}WiresharkPortable64.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string23 = /.{0,1000}wireshark\-qt.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string24 = /.{0,1000}Wireshark\-win.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string25 = /capinfos\s\-.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string26 = /captype\s\-.{0,1000}/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string27 = /rawshark\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
