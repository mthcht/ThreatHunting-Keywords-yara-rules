rule Excel
{
    meta:
        description = "Detection patterns for the tool 'Excel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Excel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: prevent any warnings or alerts when Python functions are about to be executed. Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet
        // Reference: https://github.com/tsale/Sigma_rules/blob/main/MISC/pythonfunctionwarnings_disabled.yml
        $string1 = /reg\sadd\sHKCU\\software\\policies\\microsoft\\office\\16\.0\\excel\\security\s\/v\sPythonFunctionWarnings\s\/t\sREG_DWORD\s\/d\s0\s\/f\?/ nocase ascii wide
        // Description: prevent any warnings or alerts when Python functions are about to be executed. Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet
        // Reference: https://github.com/tsale/Sigma_rules/blob/main/MISC/pythonfunctionwarnings_disabled.yml
        $string2 = /Set\-ItemProperty\s.{0,1000}\\excel\\security.{0,1000}pythonfunctionwarnings.{0,1000}0/ nocase ascii wide

    condition:
        any of them
}
