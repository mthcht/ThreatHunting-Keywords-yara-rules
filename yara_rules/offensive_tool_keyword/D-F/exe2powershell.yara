rule exe2powershell
{
    meta:
        description = "Detection patterns for the tool 'exe2powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exe2powershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string1 = /\/exe2powershell/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string2 = /exe2bat\.cpp/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string3 = /exe2bat\.exe/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string4 = /exe2powershell\.cpp/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string5 = /exe2powershell\.exe/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string6 = /exe2powershell\-master/ nocase ascii wide

    condition:
        any of them
}
