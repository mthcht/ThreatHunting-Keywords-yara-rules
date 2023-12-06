rule routerscan
{
    meta:
        description = "Detection patterns for the tool 'routerscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "routerscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Router Scan is able to find and identify a variety of devices from large number of known routers on your internal network
        // Reference: https://en.kali.tools/?p=244
        $string1 = /RouterScan\.exe/ nocase ascii wide

    condition:
        any of them
}
