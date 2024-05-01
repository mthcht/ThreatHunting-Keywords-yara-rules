rule wget
{
    meta:
        description = "Detection patterns for the tool 'wget' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wget"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: potential malicious command with wget (|sh)
        // Reference: https://x.com/CraigHRowland/status/1782938242108837896
        $string1 = /wget\s\-O\s\-\s\-q\shttp\:\/\/.{0,1000}\.jpg\|sh/ nocase ascii wide
        // Description: potential malicious command with wget (|sh)
        // Reference: https://x.com/CraigHRowland/status/1782938242108837896
        $string2 = /wget\s\-O\s\-\s\-q\shttps\:\/\/.{0,1000}\.jpg\|sh/ nocase ascii wide

    condition:
        any of them
}
