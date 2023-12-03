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
        $string1 = /.{0,1000}\snimcrypt.{0,1000}/ nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string2 = /.{0,1000}\/nimcrypt\.nim.{0,1000}/ nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string3 = /.{0,1000}\/nimcrypt\/.{0,1000}/ nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string4 = /.{0,1000}nimcrypt\s\-\-file\s.{0,1000}/ nocase ascii wide
        // Description: Nimcrypt is a .NET PE Crypter written in Nim based entirely on the work of @byt3bl33d3r's OffensiveNim project
        // Reference: https://github.com/icyguider/nimcrypt
        $string5 = /.{0,1000}\-\-out\=nimcrypt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
