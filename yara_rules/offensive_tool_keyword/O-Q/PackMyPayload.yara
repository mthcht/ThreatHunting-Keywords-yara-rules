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
        $string1 = /\s\-\-backdoor\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string2 = /\/PackMyPayload\.git/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string3 = /\/PackMyPayload\// nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string4 = /mgeeky\/PackMyPayload/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string5 = /PackMyPayload\.py/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string6 = /PackMyPayload\-master/ nocase ascii wide

    condition:
        any of them
}