rule processhacker
{
    meta:
        description = "Detection patterns for the tool 'processhacker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "processhacker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dump lsass process with processhacker
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string1 = /\<Data\sName\=\'PipeName\'\>\\lsass\<\/Data\>\<Data\sName\=\'Image\'\>.{0,1000}ProcessHacker.{0,1000}\<\/Data\>/ nocase ascii wide

    condition:
        any of them
}
