rule sysctl
{
    meta:
        description = "Detection patterns for the tool 'sysctl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sysctl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Disable echo reply for icmpsh C2
        // Reference: https://github.com/bdamele/icmpsh
        $string1 = /sysctl\s\-w\snet\.ipv4\.icmp_echo_ignore_all\=1/ nocase ascii wide

    condition:
        any of them
}
