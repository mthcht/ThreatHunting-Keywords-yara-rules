rule ATPMiniDump
{
    meta:
        description = "Detection patterns for the tool 'ATPMiniDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ATPMiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string1 = /ATPMiniDump/ nocase ascii wide

    condition:
        any of them
}
