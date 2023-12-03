rule SunCrypt
{
    meta:
        description = "Detection patterns for the tool 'SunCrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SunCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SunCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string1 = /.{0,1000}\.onion\/chat\.html\?.{0,1000}/ nocase ascii wide
        // Description: SunCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string2 = /.{0,1000}\<h2\>Why\spay\sus\?\<\/h2\>.{0,1000}/ nocase ascii wide
        // Description: SunCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string3 = /.{0,1000}YOUR_FILES_ARE_ENCRYPTED\.HTML.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
