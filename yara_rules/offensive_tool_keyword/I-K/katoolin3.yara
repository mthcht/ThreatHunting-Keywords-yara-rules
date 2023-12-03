rule katoolin3
{
    meta:
        description = "Detection patterns for the tool 'katoolin3' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "katoolin3"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Katoolin3 brings all programs available in Kali Linux to Debian and Ubuntu.
        // Reference: https://github.com/s-h-3-l-l/katoolin3
        $string1 = /.{0,1000}\/katoolin3.{0,1000}/ nocase ascii wide
        // Description: Katoolin3 brings all programs available in Kali Linux to Debian and Ubuntu.
        // Reference: https://github.com/s-h-3-l-l/katoolin3
        $string2 = /.{0,1000}\/s\-h\-3\-l\-l\/.{0,1000}/ nocase ascii wide
        // Description: Katoolin3 brings all programs available in Kali Linux to Debian and Ubuntu.
        // Reference: https://github.com/s-h-3-l-l/katoolin3
        $string3 = /.{0,1000}cd\skatoolin3.{0,1000}/ nocase ascii wide
        // Description: Katoolin3 brings all programs available in Kali Linux to Debian and Ubuntu.
        // Reference: https://github.com/s-h-3-l-l/katoolin3
        $string4 = /.{0,1000}katoolin.{0,1000}toollist\.py.{0,1000}/ nocase ascii wide
        // Description: Katoolin3 brings all programs available in Kali Linux to Debian and Ubuntu.
        // Reference: https://github.com/s-h-3-l-l/katoolin3
        $string5 = /.{0,1000}katoolin3\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
