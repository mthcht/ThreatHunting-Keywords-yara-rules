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
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string1 = /\sShell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string2 = /\/Shell3er\.git/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string3 = /\/Shell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string4 = /\/Shell3er\// nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string5 = /\\Shell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string6 = /\\Shell3er\-main/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string7 = /6334665cbd227e91e2fe4517cc5bb0e6f4163aa4ae10430e034df836287dc339/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string8 = /cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string9 = /cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string10 = /nc\s\-nlvp\s4444/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string11 = /SABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4A/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string12 = /Shell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string13 = /Welcome\sto\sthe\sMrvar0x\sPowerShell\sRemote\sShell\!/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string14 = /yehia\-mamdouh\/Shell3er/ nocase ascii wide

    condition:
        any of them
}
