rule RouterScan
{
    meta:
        description = "Detection patterns for the tool 'RouterScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RouterScan"
        rule_category = "signature_keyword"

    strings:
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string1 = /HackTool\.Win32\.RouterScan/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string2 = "HackTool:Win32/RouterScan" nocase ascii wide

    condition:
        any of them
}
