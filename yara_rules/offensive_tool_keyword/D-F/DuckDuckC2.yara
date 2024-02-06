rule DuckDuckC2
{
    meta:
        description = "Detection patterns for the tool 'DuckDuckC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DuckDuckC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A proof-of-concept C2 channel through DuckDuckGo's image proxy service
        // Reference: https://github.com/nopcorn/DuckDuckC2
        $string1 = /\/DuckDuckC2\.git/ nocase ascii wide
        // Description: A proof-of-concept C2 channel through DuckDuckGo's image proxy service
        // Reference: https://github.com/nopcorn/DuckDuckC2
        $string2 = /cd\s\sDuckDuckC2/ nocase ascii wide
        // Description: A proof-of-concept C2 channel through DuckDuckGo's image proxy service
        // Reference: https://github.com/nopcorn/DuckDuckC2
        $string3 = /DuckDuckC2\-main/ nocase ascii wide
        // Description: A proof-of-concept C2 channel through DuckDuckGo's image proxy service
        // Reference: https://github.com/nopcorn/DuckDuckC2
        $string4 = /https\:\/\/proxy\.duckduckgo\.com\/iu\/\?u\=https\:\/\/pdxkmdcepvahysnnxe\.pythonanywhere\.com\/image\.jpg\?cmd\=/ nocase ascii wide
        // Description: A proof-of-concept C2 channel through DuckDuckGo's image proxy service
        // Reference: https://github.com/nopcorn/DuckDuckC2
        $string5 = /nopcorn\/DuckDuckC2/ nocase ascii wide

    condition:
        any of them
}
