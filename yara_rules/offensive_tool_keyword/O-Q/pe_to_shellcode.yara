rule pe_to_shellcode
{
    meta:
        description = "Detection patterns for the tool 'pe_to_shellcode' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pe_to_shellcode"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Converts PE into a shellcode
        // Reference: https://github.com/hasherezade/pe_to_shellcode
        $string1 = /\/pe_to_shellcode/ nocase ascii wide
        // Description: Converts PE into a shellcode
        // Reference: https://github.com/hasherezade/pe_to_shellcode
        $string2 = /\/pe2shc\// nocase ascii wide
        // Description: Converts PE into a shellcode
        // Reference: https://github.com/hasherezade/pe_to_shellcode
        $string3 = /pe2shc\.exe\s/ nocase ascii wide

    condition:
        any of them
}
