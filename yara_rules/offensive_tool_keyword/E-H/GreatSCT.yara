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
        $string1 = /.{0,1000}\s\-c\s.{0,1000}OBFUSCATION\=.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string2 = /.{0,1000}\sGreatSCT\/.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string3 = /.{0,1000}\s\-\-list\-payloads.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string4 = /.{0,1000}\s\-\-msfoptions\s.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string5 = /.{0,1000}\/Bypass\/payloads.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string6 = /.{0,1000}\/GreatSCT\/.{0,1000}/ nocase ascii wide
        // Description: GreatSCT is a tool designed to generate metasploit payloads that bypass common anti-virus solutions and application whitelisting solutions. GreatSCT is current under support by @ConsciousHacker
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string7 = /.{0,1000}\/GreatSCT\/GreatSCT.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string8 = /.{0,1000}\/greatsct\-output.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string9 = /.{0,1000}\/regsvcs\/meterpreter.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string10 = /.{0,1000}\/regsvr32\/shellcode_inject.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string11 = /.{0,1000}func_get_powershell_dll.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string12 = /.{0,1000}func_install_wine_dotnettojscript.{0,1000}/ nocase ascii wide
        // Description: GreatSCT is a tool designed to generate metasploit payloads that bypass common anti-virus solutions and application whitelisting solutions. GreatSCT is current under support by @ConsciousHacker
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string13 = /.{0,1000}GreatSCT.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string14 = /.{0,1000}GreatSCT\.git.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string15 = /.{0,1000}GreatSCT\.py.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string16 = /.{0,1000}invoke_obfuscation\.py.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string17 = /.{0,1000}\-\-msfvenom\s.{0,1000}/ nocase ascii wide
        // Description: The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
        // Reference: https://github.com/GreatSCT/GreatSCT
        $string18 = /.{0,1000}mshta\/shellcode_inject.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
