rule Mshikaki
{
    meta:
        description = "Detection patterns for the tool 'Mshikaki' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mshikaki"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string1 = /.{0,1000}\sMshikaki\.cpp.{0,1000}/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string2 = /.{0,1000}\/Mshikaki\.git.{0,1000}/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string3 = /.{0,1000}\\Mshikaki\.cpp.{0,1000}/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string4 = /.{0,1000}Mshikaki\.exe.{0,1000}/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string5 = /.{0,1000}Mshikaki\-main.{0,1000}/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string6 = /.{0,1000}trevorsaudi\/Mshikaki.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
