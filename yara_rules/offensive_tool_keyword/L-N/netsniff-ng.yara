rule netsniff_ng
{
    meta:
        description = "Detection patterns for the tool 'netsniff-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsniff-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: netsniff-ng is a high performance Linux network sniffer for packet inspection. It can be used for protocol analysis. reverse engineering or network debugging. The gain of performance is reached by 'zero-copy' mechanisms. so that the kernel does not need to copy packets from kernelspace to userspace.
        // Reference: https://packages.debian.org/fr/sid/netsniff-ng
        $string1 = /netsniff\-ng/ nocase ascii wide

    condition:
        any of them
}
