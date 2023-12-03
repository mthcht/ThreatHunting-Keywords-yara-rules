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
        $string1 = /.{0,1000}bdamele\/icmpsh.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string2 = /.{0,1000}icmpsh\.exe.{0,1000}/ nocase ascii wide
        // Description: Simple reverse ICMP shell
        // Reference: https://github.com/bdamele/icmpsh
        $string3 = /.{0,1000}icmpsh\.git.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string4 = /.{0,1000}icmpsh_m\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string5 = /.{0,1000}icmpsh\-m\..{0,1000}/ nocase ascii wide
        // Description: Simple reverse ICMP shell
        // Reference: https://github.com/bdamele/icmpsh
        $string6 = /.{0,1000}icmpsh\-master.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string7 = /.{0,1000}icmpsh\-s\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
