rule Shellcode_Loader
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Loader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Loader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dynamic shellcode loading
        // Reference: https://github.com/ReversingID/Shellcode-Loader
        $string1 = /\/Shellcode\-Loader\.git/ nocase ascii wide
        // Description: dynamic shellcode loading
        // Reference: https://github.com/ReversingID/Shellcode-Loader
        $string2 = /C\:\\Windows\\DirectX\.log.{0,1000}\\Windows\\Temp\\backup\.log/ nocase ascii wide
        // Description: dynamic shellcode loading
        // Reference: https://github.com/ReversingID/Shellcode-Loader
        $string3 = /ReversingID\/Shellcode\-Loader/ nocase ascii wide
        // Description: dynamic shellcode loading
        // Reference: https://github.com/ReversingID/Shellcode-Loader
        $string4 = /Shellcode\-Loader\-master/ nocase ascii wide

    condition:
        any of them
}
