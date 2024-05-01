rule curl
{
    meta:
        description = "Detection patterns for the tool 'curl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "curl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: potential suspicious curl command - downloading payload in the temp directory
        // Reference: https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/
        $string1 = /cmd\.exe.{0,1000}\s\/c\secho\scurl\shttps\:\/\/.{0,1000}\s\-\-output\s\"\%temp\%.{0,1000}\s\-\-ssl\sno\-revoke\s\-\-insecure\s\-\-location\s\>\s\"\%temp\%/ nocase ascii wide
        // Description: potential malicious command with curl (|sh)
        // Reference: https://x.com/CraigHRowland/status/1782938242108837896
        $string2 = /curl\shttp\:\/\/.{0,1000}\.png\s\-k\|dd\sskip\=2446\sbs\=1\|sh/ nocase ascii wide
        // Description: potential malicious command with curl (|sh)
        // Reference: https://x.com/CraigHRowland/status/1782938242108837896
        $string3 = /curl\shttps\:\/\/.{0,1000}\.png\s\-k\|dd\sskip\=2446\sbs\=1\|sh/ nocase ascii wide

    condition:
        any of them
}
