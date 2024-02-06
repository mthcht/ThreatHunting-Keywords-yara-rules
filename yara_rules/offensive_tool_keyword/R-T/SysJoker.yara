rule SysJoker
{
    meta:
        description = "Detection patterns for the tool 'SysJoker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SysJoker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string1 = /\:\\ProgramData\\RecoverySystem\\recoveryWindows\.zip/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string2 = /\:\\ProgramData\\SystemData\\igfxCUIService\.exe/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string3 = /\:\\ProgramData\\SystemData\\tempo1\.txt/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string4 = /\:\\ProgramData\\SystemData\\tempo2\.txt/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string5 = /C\:\\ProgramData\\SystemData\\microsoft_Windows\.dll/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string6 = /REG\sADD\s.{0,1000}igfxCUIService/ nocase ascii wide

    condition:
        any of them
}
