rule EventLogCrasher
{
    meta:
        description = "Detection patterns for the tool 'EventLogCrasher' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventLogCrasher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string1 = /\sRegisterEventSourceW\(L\"DESKTOP\-\.\.\.\".{0,1000}\sL\"1337/ nocase ascii wide
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string2 = /\/EventLogCrasher\.git/ nocase ascii wide
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string3 = /\\EventLogCrasher\\/ nocase ascii wide
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string4 = /corrupt\sdata\sthat\swas\smarshalled\sby\sNdr64ConformantVaryingArrayMarshall/ nocase ascii wide
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string5 = /eventlog_dos\.exe/ nocase ascii wide
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string6 = /EventLogCrasher\.exe/ nocase ascii wide
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string7 = /EventLogCrasher\-main/ nocase ascii wide
        // Description: crash the Windows Event Log service of any other Windows 10/Windows Server 2022 machine on the same domain
        // Reference: https://github.com/floesen/EventLogCrasher
        $string8 = /floesen\/EventLogCrasher/ nocase ascii wide

    condition:
        any of them
}
