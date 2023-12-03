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
        $string1 = /.{0,1000}:\\ProgramData\\RecoverySystem\\recoveryWindows\.zip.{0,1000}/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string2 = /.{0,1000}:\\ProgramData\\SystemData\\igfxCUIService\.exe.{0,1000}/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string3 = /.{0,1000}:\\ProgramData\\SystemData\\tempo1\.txt.{0,1000}/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string4 = /.{0,1000}:\\ProgramData\\SystemData\\tempo2\.txt.{0,1000}/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string5 = /.{0,1000}C:\\ProgramData\\SystemData\\microsoft_Windows\.dll.{0,1000}/ nocase ascii wide
        // Description: SysJoker backdoor - multi-platform backdoor that targets Windows Mac and Linux
        // Reference: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
        $string6 = /.{0,1000}REG\sADD\s.{0,1000}igfxCUIService.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
