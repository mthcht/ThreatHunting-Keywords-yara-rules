rule sdelete
{
    meta:
        description = "Detection patterns for the tool 'sdelete' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sdelete"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SDelete is an application that securely deletes data in a way that makes it unrecoverable.- abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string1 = /\/sdelete\.exe/ nocase ascii wide
        // Description: SDelete is an application that securely deletes data in a way that makes it unrecoverable.- abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string2 = /\/SDelete\.zip/ nocase ascii wide
        // Description: SDelete is an application that securely deletes data in a way that makes it unrecoverable.- abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string3 = /\/sdelete64\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string4 = /\/sdelete64a\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string5 = /\\sdelete\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string6 = /\\SDelete\.zip/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string7 = /\\sdelete64\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string8 = /\\sdelete64a\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string9 = /\\Software\\Sysinternals\\Sdelete/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string10 = /\>sdelete\.exe\</ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string11 = ">sysinternals sdelete<" nocase ascii wide

    condition:
        any of them
}
