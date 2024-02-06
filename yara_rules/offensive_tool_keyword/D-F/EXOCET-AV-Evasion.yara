rule EXOCET_AV_Evasion
{
    meta:
        description = "Detection patterns for the tool 'EXOCET-AV-Evasion' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EXOCET-AV-Evasion"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string1 = /\sexocet\.go\s.{0,1000}\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string2 = /\/exocet\.elf/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string3 = /\/exocet\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string4 = /\/EXOCET\-AV\-Evasion\.git/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string5 = /\\beacon\-in\-go\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string6 = /\\exocet\.elf/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string7 = /\\exocet\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string8 = /\\inline\-shellcode\-test\.c/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string9 = /EXOCET\-AV\-Evasion\-master/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string10 = /exocet\-shellcode\-exec\-redo\.go/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string11 = /func\sdecryptMalware\(/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string12 = /meterpreter\-in\-go\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string13 = /Output\smalware\ssample\sselected\:\s/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string14 = /tanc7\/EXOCET\-AV\-Evasion/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string15 = /The\smalware\sGo\sfile\shas\sbeen\scompleted\./ nocase ascii wide

    condition:
        any of them
}
