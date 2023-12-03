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
        $string1 = /.{0,1000}\/SysmonQuiet.{0,1000}/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string2 = /.{0,1000}Sysmon\sis\sbeing\ssuffocated.{0,1000}/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string3 = /.{0,1000}Sysmon\sis\squiet\snow\!.{0,1000}/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string4 = /.{0,1000}sysmonquiet\..{0,1000}/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string5 = /.{0,1000}SysmonQuiet\-main.{0,1000}/ nocase ascii wide
        // Description: RDLL for Cobalt Strike beacon to silence Sysmon process
        // Reference: https://github.com/ScriptIdiot/SysmonQuiet
        $string6 = /.{0,1000}Yay\!\sNo\sSYSMON\shere\!.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
