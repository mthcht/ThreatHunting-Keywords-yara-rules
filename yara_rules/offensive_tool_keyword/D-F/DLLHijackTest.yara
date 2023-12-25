rule DLLHijackTest
{
    meta:
        description = "Detection patterns for the tool 'DLLHijackTest' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLLHijackTest"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string1 = /\/DLLHijackTest\.git/ nocase ascii wide
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string2 = /\[\+\]\sParsed\sProcmon\soutput\sfor\spotential\sDLL\shijack\spaths\!/ nocase ascii wide
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string3 = /644758B1\-C146\-4D3B\-B614\-8EB6C933B0AA/ nocase ascii wide
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string4 = /DLLHijackTest\.dll/ nocase ascii wide
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string5 = /DLLHijackTest\.sln/ nocase ascii wide
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string6 = /DLLHijackTest\-master/ nocase ascii wide
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string7 = /Get\-PotentialDLLHijack/ nocase ascii wide
        // Description: DLL and PowerShell script to assist with finding DLL hijacks
        // Reference: https://github.com/slyd0g/DLLHijackTest
        $string8 = /slyd0g\/DLLHijackTest/ nocase ascii wide

    condition:
        any of them
}
