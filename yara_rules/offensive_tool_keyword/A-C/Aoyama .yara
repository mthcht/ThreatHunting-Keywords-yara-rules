rule Aoyama_
{
    meta:
        description = "Detection patterns for the tool 'Aoyama ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Aoyama "
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string1 = "#Code By Leeon123" nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string2 = /\[\!\]\sSetting\sUp\sC\&C\sModule/ nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string3 = /\[\!\]\sWelcom\sto\sthe\sAoyama\sC\&C\sServer/ nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string4 = "==> Python3 C&C server <==" nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string5 = "43f5ef8c625efba630bb99fd4ae086008ebed5c2f3386f1b43bbe8ee7c06f591" nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string6 = "Leeon123/Aoyama" nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string7 = "Leeon123/Python3-botnet" nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string8 = /python3\scnc\.py/ nocase ascii wide
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string9 = "rm -rf /bin/netstat"
        // Description: Python Botnet 
        // Reference: https://github.com/Leeon123/Aoyama
        $string10 = /rm\s\-rf\s\~\/\.bash_history/

    condition:
        any of them
}
