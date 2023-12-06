rule wifigrabber
{
    meta:
        description = "Detection patterns for the tool 'wifigrabber' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifigrabber"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: grab wifi password and exfiltrate to a given site
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/wifigrabber
        $string1 = /\s\>\sWi\-Fi\-PASS/ nocase ascii wide
        // Description: grab wifi password and exfiltrate to a given site
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/wifigrabber
        $string2 = /\s\-InFile\sWi\-Fi\-PASS/ nocase ascii wide
        // Description: grab wifi password and exfiltrate to a given site
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/wifigrabber
        $string3 = /\/credentials\/wifigrabber/ nocase ascii wide
        // Description: grab wifi password and exfiltrate to a given site
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/wifigrabber
        $string4 = /String\snetsh\swlan\sexport\sprofile\skey\=clear/ nocase ascii wide

    condition:
        any of them
}
