rule UniByAv
{
    meta:
        description = "Detection patterns for the tool 'UniByAv' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UniByAv"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UniByAv is a simple obfuscator that take raw shellcode and generate executable that are Anti-Virus friendly. The obfuscation routine is purely writtend in assembly to remain pretty short and efficient. In a nutshell the application generate a 32 bits xor key and brute force the key at run time then perform the decryption of the actually shellcode.
        // Reference: https://github.com/Mr-Un1k0d3r/UniByAv
        $string1 = /UniByAv/ nocase ascii wide

    condition:
        any of them
}
