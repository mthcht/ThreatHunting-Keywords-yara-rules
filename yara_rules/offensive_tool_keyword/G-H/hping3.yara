rule hping3
{
    meta:
        description = "Detection patterns for the tool 'hping3' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hping3"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HPING3 DoS
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string1 = /hping3\s.{0,1000}\s\-\-flood\s\-\-frag\s\-\-spoof\s.{0,1000}\s\-\-destport/ nocase ascii wide

    condition:
        any of them
}
