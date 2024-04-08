rule vbad
{
    meta:
        description = "Detection patterns for the tool 'vbad' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vbad"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string1 = /\sfake\ssmall\skeys\sbefore\sreal\sones\"/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string2 = /\swill\sbe\sobfuscated\sand\sintegrated\sin\screated\sdocuments/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string3 = /\/VBad\.git/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string4 = /\\VBad\.py/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string5 = /7af0afcd0f9db86c97a7357aaaedd26ab3746e828d5c0febdd063099d0d3fee9/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string6 = /Pepitoh\/VBad/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string7 = /VBA\sObfuscation\sTools\scombined\swith\san\sMS\soffice\sdocument\sgenerator/ nocase ascii wide
        // Description: VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
        // Reference: https://github.com/Pepitoh/Vbad
        $string8 = /Vbad\/VBad\.py/ nocase ascii wide

    condition:
        any of them
}
