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
        $string1 = /\sKeeTheft\.exe/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string2 = /\/KeeThief\.git/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string3 = /\\KeeTheft\.exe/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string4 = /KeeTheft\/Dinvoke/ nocase ascii wide
        // Description: Patch GhostPack/KeeThief for it to use DInvoke and syscalls
        // Reference: https://github.com/Metro-Holografix/KeeThiefSyscalls
        $string5 = /KeeThiefSyscalls/ nocase ascii wide

    condition:
        any of them
}
