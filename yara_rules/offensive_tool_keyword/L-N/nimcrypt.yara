rule nimcrypt
{
    meta:
        description = "Detection patterns for the tool 'nimcrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimcrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string1 = /\snimcrypt/ nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string2 = /\/nimcrypt\.nim/ nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string3 = /\/nimcrypt\// nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string4 = /nimcrypt\s\-\-file\s/ nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string5 = /\-\-out\=nimcrypt/ nocase ascii wide

    condition:
        any of them
}
