rule Shell3er
{
    meta:
        description = "Detection patterns for the tool 'Shell3er' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shell3er"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string1 = /\/Shell3er\// nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string2 = /cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string3 = /nc\s\-nlvp\s4444/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string4 = /Shell3er\.ps1/ nocase ascii wide

    condition:
        any of them
}