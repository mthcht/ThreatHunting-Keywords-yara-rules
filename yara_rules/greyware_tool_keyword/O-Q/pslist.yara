rule pslist
{
    meta:
        description = "Detection patterns for the tool 'pslist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pslist"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Microsoft sysinternal comandline tool to list running process abused by threat actors
        // Reference: https://learn.microsoft.com/pt-br/sysinternals/downloads/pslist
        $string1 = /\/pslist\.exe/ nocase ascii wide
        // Description: Microsoft sysinternal comandline tool to list running process abused by threat actors
        // Reference: https://learn.microsoft.com/pt-br/sysinternals/downloads/pslist
        $string2 = /\/pslist64\.exe/ nocase ascii wide
        // Description: Microsoft sysinternal comandline tool to list running process abused by threat actors
        // Reference: https://learn.microsoft.com/pt-br/sysinternals/downloads/pslist
        $string3 = /\\pslist\.exe/ nocase ascii wide
        // Description: Microsoft sysinternal comandline tool to list running process abused by threat actors
        // Reference: https://learn.microsoft.com/pt-br/sysinternals/downloads/pslist
        $string4 = /\\pslist64\.exe/ nocase ascii wide
        // Description: Microsoft sysinternal comandline tool to list running process abused by threat actors
        // Reference: https://learn.microsoft.com/pt-br/sysinternals/downloads/pslist
        $string5 = /\>Sysinternals\sPsList\</ nocase ascii wide
        // Description: Microsoft sysinternal comandline tool to list running process abused by threat actors
        // Reference: https://learn.microsoft.com/pt-br/sysinternals/downloads/pslist
        $string6 = /d3247f03dcd7b9335344ebba76a0b92370f32f1cb0e480c734da52db2bd8df60/ nocase ascii wide

    condition:
        any of them
}
