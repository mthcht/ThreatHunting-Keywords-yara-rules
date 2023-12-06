rule cobaltstrike
{
    meta:
        description = "Detection patterns for the tool 'cobaltstrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cobaltstrike"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: If cobaltstrike uses execute-assembly there is a chance that a file will be created in the UsageLogs logs
        // Reference: https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/
        $string1 = /\\AppData\\Local\\Microsoft\\CLR_.{0,1000}\\UsageLogs\\.{0,1000}\.exe\.log/ nocase ascii wide

    condition:
        any of them
}
