rule PE_Obfuscator
{
    meta:
        description = "Detection patterns for the tool 'PE-Obfuscator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PE-Obfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string1 = /.{0,1000}\/PE\-Obfuscator.{0,1000}/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string2 = /.{0,1000}\\out_pe\.exe.{0,1000}/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string3 = /.{0,1000}PE\-Obfuscator\.exe.{0,1000}/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string4 = /.{0,1000}PE\-Obfuscator\.git.{0,1000}/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string5 = /.{0,1000}PE\-Obfuscator\-main.{0,1000}/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string6 = /.{0,1000}script\/xor\-bin\.py.{0,1000}/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string7 = /.{0,1000}xor\-bin\.py\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
