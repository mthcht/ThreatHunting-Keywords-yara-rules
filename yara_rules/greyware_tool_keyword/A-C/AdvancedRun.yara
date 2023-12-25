rule AdvancedRun
{
    meta:
        description = "Detection patterns for the tool 'AdvancedRun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdvancedRun"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: nirsoft tool  - Run a program with different settings that you choose
        // Reference: https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3
        $string1 = /AdvancedRun\.exe\s\/EXEFilename\s.{0,1000}\\sc\.exe.{0,1000}stop\sWinDefend/ nocase ascii wide

    condition:
        any of them
}
