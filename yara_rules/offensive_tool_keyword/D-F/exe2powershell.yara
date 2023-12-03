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
        $string1 = /.{0,1000}\/exe2powershell.{0,1000}/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string2 = /.{0,1000}exe2bat\.cpp.{0,1000}/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string3 = /.{0,1000}exe2bat\.exe.{0,1000}/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string4 = /.{0,1000}exe2powershell\.cpp.{0,1000}/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string5 = /.{0,1000}exe2powershell\.exe.{0,1000}/ nocase ascii wide
        // Description: exe2powershell is used to convert any binary file to a bat/powershell file
        // Reference: https://github.com/yanncam/exe2powershell
        $string6 = /.{0,1000}exe2powershell\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
