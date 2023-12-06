rule fgdump
{
    meta:
        description = "Detection patterns for the tool 'fgdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fgdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string1 = /cachedump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string2 = /cachedump64\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string3 = /fgdump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string4 = /fgexec\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string5 = /pstgdump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string6 = /pwdump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string7 = /servpw\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string8 = /servpw64\.exe/ nocase ascii wide

    condition:
        any of them
}
