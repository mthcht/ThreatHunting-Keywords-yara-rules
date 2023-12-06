rule icmpsh
{
    meta:
        description = "Detection patterns for the tool 'icmpsh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icmpsh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string1 = /bdamele\/icmpsh/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string2 = /icmpsh\.exe/ nocase ascii wide
        // Description: Simple reverse ICMP shell
        // Reference: https://github.com/bdamele/icmpsh
        $string3 = /icmpsh\.git/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string4 = /icmpsh_m\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string5 = /icmpsh\-m\./ nocase ascii wide
        // Description: Simple reverse ICMP shell
        // Reference: https://github.com/bdamele/icmpsh
        $string6 = /icmpsh\-master/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string7 = /icmpsh\-s\./ nocase ascii wide

    condition:
        any of them
}
