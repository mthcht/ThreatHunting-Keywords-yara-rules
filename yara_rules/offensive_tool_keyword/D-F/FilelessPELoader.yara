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
        $string1 = /\/FilelessPELoader/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string2 = /82277B35\-D159\-4B44\-8D54\-FB66EDD58D5C/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string3 = /AES_cryptor\.py\s/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string4 = /FilelessPELoader\.cpp/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string5 = /FilelessPELoader\.exe/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string6 = /FilelessPELoader\.vcxproj/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string7 = /FilelessPELoader\-main/ nocase ascii wide
        // Description: Loading Remote AES Encrypted PE in memory - Decrypted it and run it
        // Reference: https://github.com/TheD1rkMtr/FilelessPELoader
        $string8 = /mimikatz\.exe/ nocase ascii wide

    condition:
        any of them
}
