rule psobf
{
    meta:
        description = "Detection patterns for the tool 'psobf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psobf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell Obfuscator
        // Reference: https://github.com/TaurusOmar/psobf
        $string1 = /\.\/obfuscator\s\-i\s.{0,1000}\.ps1/ nocase ascii wide
        // Description: PowerShell Obfuscator
        // Reference: https://github.com/TaurusOmar/psobf
        $string2 = /\/psobf\.git/ nocase ascii wide
        // Description: PowerShell Obfuscator
        // Reference: https://github.com/TaurusOmar/psobf
        $string3 = /f3b1f6c6ca346acab1afd2dc61c43588f4c0914c1a6d1247db3a46bbd3421b38/ nocase ascii wide
        // Description: PowerShell Obfuscator
        // Reference: https://github.com/TaurusOmar/psobf
        $string4 = /Invoke\-Expression\s\$obfuscated/ nocase ascii wide
        // Description: PowerShell Obfuscator
        // Reference: https://github.com/TaurusOmar/psobf
        $string5 = /TaurusOmar\/psobf/ nocase ascii wide

    condition:
        any of them
}
