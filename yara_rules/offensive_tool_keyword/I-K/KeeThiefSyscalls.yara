rule KeeThiefSyscalls
{
    meta:
        description = "Detection patterns for the tool 'KeeThiefSyscalls' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeeThiefSyscalls"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string1 = /.{0,1000}\sKeeTheft\.exe.{0,1000}/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string2 = /.{0,1000}\/KeeThief\.git.{0,1000}/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string3 = /.{0,1000}\\KeeTheft\.exe.{0,1000}/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string4 = /.{0,1000}KeeTheft\/Dinvoke.{0,1000}/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string5 = /.{0,1000}KeeThiefSyscalls.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
