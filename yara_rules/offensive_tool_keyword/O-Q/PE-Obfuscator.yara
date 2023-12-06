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
        $string1 = /\/PE\-Obfuscator/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string2 = /\\out_pe\.exe/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string3 = /PE\-Obfuscator\.exe/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string4 = /PE\-Obfuscator\.git/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string5 = /PE\-Obfuscator\-main/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string6 = /script\/xor\-bin\.py/ nocase ascii wide
        // Description: PE obfuscator with Evasion in mind
        // Reference: https://github.com/TheD1rkMtr/PE-Obfuscator
        $string7 = /xor\-bin\.py\s.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
