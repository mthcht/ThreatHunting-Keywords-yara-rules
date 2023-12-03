rule PackMyPayload
{
    meta:
        description = "Detection patterns for the tool 'PackMyPayload' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PackMyPayload"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string1 = /.{0,1000}\s\-\-backdoor\s.{0,1000}/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string2 = /.{0,1000}\/PackMyPayload\.git.{0,1000}/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string3 = /.{0,1000}\/PackMyPayload\/.{0,1000}/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string4 = /.{0,1000}mgeeky\/PackMyPayload.{0,1000}/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string5 = /.{0,1000}PackMyPayload\.py.{0,1000}/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string6 = /.{0,1000}PackMyPayload\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
