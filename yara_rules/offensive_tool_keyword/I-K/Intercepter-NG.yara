rule Intercepter_NG
{
    meta:
        description = "Detection patterns for the tool 'Intercepter-NG' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Intercepter-NG"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string1 = /\/Intercepter\-NG.{0,1000}\.apk/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string2 = /http\:\/\/sniff\.su\/.{0,1000}\.gz/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string3 = /http\:\/\/sniff\.su\/.{0,1000}\.zip/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string4 = /https\:\/\/sniff\.su\/.{0,1000}\.gz/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string5 = /https\:\/\/sniff\.su\/.{0,1000}\.zip/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string6 = /Intercepter\-NG/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string7 = /Intercepter\-NG\-1\.0\.zip/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string8 = /Intercepter\-NG\-1\.3\.zip/ nocase ascii wide
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string9 = /sniff\.su\/Intercepter\-NG/ nocase ascii wide

    condition:
        any of them
}
