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

    condition:
        any of them
}