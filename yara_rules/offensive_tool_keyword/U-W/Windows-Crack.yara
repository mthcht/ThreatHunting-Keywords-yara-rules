rule Windows_Crack
{
    meta:
        description = "Detection patterns for the tool 'Windows-Crack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Windows-Crack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/japd06/Windows-Crack/
        $string1 = /REG\sADD\s\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe\"\s\/v\sDebugger\s\/t\sREG_SZ\s\/d\s\"C\:\\windows\\system32\\cmd\.exe\"/ nocase ascii wide

    condition:
        any of them
}
