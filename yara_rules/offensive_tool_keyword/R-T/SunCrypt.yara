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
        $string1 = /\.onion\/chat\.html\?/ nocase ascii wide
        // Description: SunCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string2 = /\<h2\>Why\spay\sus\?\<\/h2\>/ nocase ascii wide
        // Description: SunCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string3 = /YOUR_FILES_ARE_ENCRYPTED\.HTML/ nocase ascii wide

    condition:
        any of them
}
