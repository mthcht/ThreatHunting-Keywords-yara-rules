rule FilelessPELoader
{
    meta:
        description = "Detection patterns for the tool 'FilelessPELoader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FilelessPELoader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string1 = /.{0,1000}\/FilelessPELoader.{0,1000}/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string2 = /.{0,1000}82277B35\-D159\-4B44\-8D54\-FB66EDD58D5C.{0,1000}/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string3 = /.{0,1000}AES_cryptor\.py\s.{0,1000}/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string4 = /.{0,1000}FilelessPELoader\.cpp.{0,1000}/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string5 = /.{0,1000}FilelessPELoader\.exe.{0,1000}/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string6 = /.{0,1000}FilelessPELoader\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string7 = /.{0,1000}FilelessPELoader\-main.{0,1000}/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string8 = /.{0,1000}mimikatz\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
