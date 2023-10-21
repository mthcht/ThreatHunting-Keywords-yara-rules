rule Procdump
{
    meta:
        description = "Detection patterns for the tool 'Procdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Procdump"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string1 = /procdump.*lsass/ nocase ascii wide

    condition:
        any of them
}