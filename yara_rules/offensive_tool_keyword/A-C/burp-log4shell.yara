rule burp_log4shell
{
    meta:
        description = "Detection patterns for the tool 'burp-log4shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "burp-log4shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string1 = "00bef672112754668bde734e62d22239737350e0d16b2984990f097d0db51c02" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string2 = "05dd50b46ccb4f52cd5c44cdf5387de164753bbc9f4d6adae943a3077c7c1a55" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string3 = "41dc2afeaea216cd8e1f2fdd3974b2bc80fe0df8e909f9ab7bfea34979bd6a0d" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string4 = "541408686147c9ba7d59b1b4430addb3aabcf0033353ed1140d182243012b934" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string5 = "7d2a1f11107cf703d1bc2eb6cf4e2627d1eec923852b4a3230b7e79ca2542587" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string6 = "7ea370e3fb26387369e0d4f173cbf6df072ab2f6b3c4de43795e6fc1c1e74af3" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string7 = "8bc182681dd24661db50888cc4a7faf05d3e7d79a7447af14337f14ff58d7453" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string8 = "a285f5f5627c483cdc0a2d2110ea1840ae221bcbf836a186822835653db93a71" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string9 = "b35ef52872291ca02dd05f9caba9ac7f93b81407c253d7746673ca51c53d1c52" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string10 = "b949f1eeba7260b233e58123507605328133428e37bbccb6aa2dd9ba68cf18b5" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string11 = /burp\-log4shell\.jar/ nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string12 = "caa3c8d1a294def75b384c1bdfc7fab039da2d0e6c66beaae798adb0d9a22da4" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string13 = "ccaf8dda0e6569f46a12db288dbfeff95b91fdfa7beac679624e141dc92b05b2" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string14 = "d73ce38475b90ce68cb44cbaa7f76b091e06a970aba887a248e8bff5e9b46b57" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string15 = "da817f811f9c4b3f118d78bffcccafd6f1a8cb21e505305f6ae45e1583982abc" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string16 = "e301dcccae011793013ea604a8e7cbd343595fa78d09f38b2776740a55a308c8" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string17 = "e34e1d947623610df05776c55c67f5252dd01a0f21ed33dd48c4b0402f564173" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string18 = "e39b03c7268e363e670b40a4c5e65d5c04fc82557ea2abaa57e0e9b7403bdf61" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string19 = "e3de5481632991feec94a6faf2404118c5b8ee31e74fe54594cec8bf2d03c99d" nocase ascii wide
        // Description: Log4Shell scanner for Burp Suite
        // Reference: https://github.com/silentsignal/burp-log4shell
        $string20 = /log4shell\-scanner\.jar/ nocase ascii wide

    condition:
        any of them
}
