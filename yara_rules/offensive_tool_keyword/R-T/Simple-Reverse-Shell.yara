rule Simple_Reverse_Shell
{
    meta:
        description = "Detection patterns for the tool 'Simple-Reverse-Shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Simple-Reverse-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple C++ reverse shell without obfuscation to avoid Win 11 defender detection (At the time of publication
        // Reference: https://github.com/tihanyin/Simple-Reverse-Shell/
        $string1 = /\/Simple\-Reverse\-Shell/ nocase ascii wide

    condition:
        any of them
}
