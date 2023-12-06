rule sysmonquiet
{
    meta:
        description = "Detection patterns for the tool 'sysmonquiet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sysmonquiet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string1 = /\/SysmonQuiet/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string2 = /Sysmon\sis\sbeing\ssuffocated/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string3 = /Sysmon\sis\squiet\snow\!/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string4 = /sysmonquiet\./ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string5 = /SysmonQuiet\-main/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string6 = /Yay\!\sNo\sSYSMON\shere\!/ nocase ascii wide

    condition:
        any of them
}
