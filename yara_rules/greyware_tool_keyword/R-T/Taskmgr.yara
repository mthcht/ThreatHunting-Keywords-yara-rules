rule Taskmgr
{
    meta:
        description = "Detection patterns for the tool 'Taskmgr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Taskmgr"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dump lsass process with Taskmgr
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string1 = /\<Data\sName\=\'PipeName\'\>\\lsass\<\/Data\>\<Data\sName\=\'Image\'\>C\:\\Windows\\System32\\Taskmgr\.exe\<\/Data\>/ nocase ascii wide

    condition:
        any of them
}
