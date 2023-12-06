rule IKEForce
{
    meta:
        description = "Detection patterns for the tool 'IKEForce' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IKEForce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: IKEForce is a command line IPSEC VPN brute forcing tool for Linux that allows group name/ID enumeration and XAUTH brute forcing capabilities.
        // Reference: https://github.com/SpiderLabs/ikeforce
        $string1 = /\/IKEForce/ nocase ascii wide
        // Description: IKEForce is a command line IPSEC VPN brute forcing tool for Linux that allows group name/ID enumeration and XAUTH brute forcing capabilities.
        // Reference: https://github.com/SpiderLabs/ikeforce
        $string2 = /ikeforce\.py/ nocase ascii wide

    condition:
        any of them
}
