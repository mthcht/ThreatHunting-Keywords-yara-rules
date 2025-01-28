rule icacls
{
    meta:
        description = "Detection patterns for the tool 'icacls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icacls"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string1 = /icacls\s\\"\%appdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string2 = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string3 = /icacls\s\\"\%programdata\%\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string4 = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string5 = /icacls\s\\"C\:\\Documents\sand\sSettings\\\%username\%\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string6 = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\"\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string7 = /icacls\s\\"C\:\\Documents\sand\sSettings\\All\sUsers\\Start\sMenu\\Programs\\Startup\\.{0,1000}\\"\s2\>nul/ nocase ascii wide

    condition:
        any of them
}
