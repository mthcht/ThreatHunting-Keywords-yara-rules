rule MacroMeter
{
    meta:
        description = "Detection patterns for the tool 'MacroMeter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MacroMeter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VBA Reversed TCP Meterpreter Stager CSharp Meterpreter Stager build by Cn33liz and embedded within VBA using DotNetToJScript from James Forshaw https://github.com/tyranid/DotNetToJScript
        // Reference: https://github.com/Cn33liz/MacroMeter
        $string1 = /\/MacroMeter/ nocase ascii wide
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string2 = /\\tricky\.ps1/ nocase ascii wide

    condition:
        any of them
}
