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
        $string1 = /\sMshikaki\.cpp/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string2 = /\/Mshikaki\.git/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string3 = /\\Mshikaki\.cpp/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string4 = /Mshikaki\.exe/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string5 = /Mshikaki\-main/ nocase ascii wide
        // Description: A shellcode injection tool capable of bypassing AMSI. Features the QueueUserAPC() injection technique and supports XOR encryption
        // Reference: https://github.com/trevorsaudi/Mshikaki
        $string6 = /trevorsaudi\/Mshikaki/ nocase ascii wide

    condition:
        any of them
}
