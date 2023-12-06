rule GreatSCT
{
    meta:
        description = "Detection patterns for the tool 'GreatSCT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GreatSCT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string1 = /\s\-c\s.{0,1000}OBFUSCATION\=.{0,1000}\.ps1/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string2 = /\sGreatSCT\// nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string3 = /\s\-\-list\-payloads/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string4 = /\s\-\-msfoptions\s/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string5 = /\/Bypass\/payloads/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string6 = /\/GreatSCT\// nocase ascii wide
        // Description: GreatSCT is a tool designed to generate metasploit payloads that bypass common anti-virus solutions and application whitelisting solutions. GreatSCT is current under support by @ConsciousHacker
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string7 = /\/GreatSCT\/GreatSCT/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string8 = /\/greatsct\-output/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string9 = /\/regsvcs\/meterpreter/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string10 = /\/regsvr32\/shellcode_inject/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string11 = /func_get_powershell_dll/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string12 = /func_install_wine_dotnettojscript/ nocase ascii wide
        // Description: GreatSCT is a tool designed to generate metasploit payloads that bypass common anti-virus solutions and application whitelisting solutions. GreatSCT is current under support by @ConsciousHacker
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string13 = /GreatSCT/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string14 = /GreatSCT\.git/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string15 = /GreatSCT\.py/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string16 = /invoke_obfuscation\.py/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string17 = /\-\-msfvenom\s/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string18 = /mshta\/shellcode_inject/ nocase ascii wide

    condition:
        any of them
}
