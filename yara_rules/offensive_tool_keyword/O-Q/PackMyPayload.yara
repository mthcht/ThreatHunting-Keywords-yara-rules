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
        $string4 = /\[\+\]\sBackdoored\sexisting\s7zip\swith\sspecified\sinput\sfile/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string5 = /\[\+\]\sBackdoored\sexisting\sISO\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string6 = /\[\+\]\sBackdoored\sexisting\sMSI\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string7 = /\[\+\]\sBackdoored\sexisting\sVHD\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string8 = /Backdooring\sMSI\sfiles\sis\scurrently\snot\ssupported\./ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string9 = /ddde81ecf809882929faefd5887095a9d8671979f0c4d68579fa8b3a07674768/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string10 = /File\sspecifed\sto\sbackdoor\sdoes\snot\sexist\:\s/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string11 = /mgeeky\/PackMyPayload/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string12 = /PackMyPayload\.py/ nocase ascii wide
        // Description: A PoC that packages payloads into output containers to evade Mark-of-the-Web flag & demonstrate risks associated with container file formats
        // Reference: https://github.com/mgeeky/PackMyPayload/
        $string13 = /PackMyPayload\-master/ nocase ascii wide

    condition:
        any of them
}
