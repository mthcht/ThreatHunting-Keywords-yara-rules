rule Salsa_tools
{
    meta:
        description = "Detection patterns for the tool 'Salsa-tools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Salsa-tools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Salsa Tools - An AV-Safe Reverse Shell dipped on bellota sauce Salsa Tools is a collection of three different tools that combined. allows you to get a reverse shell on steroids in any Windows environment without even needing PowerShell for its execution. In order to avoid the latest detection techniques (AMSI). most of the components were initially written on C#. Salsa Tools was publicly released by Luis Vacas during his Talk Inmersin en la explotacin tiene rima which took place during h-c0n in 9th February 2019
        // Reference: https://github.com/Hackplayers/Salsa-tools
        $string1 = /Salsa\-tools/ nocase ascii wide

    condition:
        any of them
}
