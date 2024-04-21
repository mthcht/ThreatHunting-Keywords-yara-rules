rule Shoggoth
{
    meta:
        description = "Detection patterns for the tool 'Shoggoth' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shoggoth"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string1 = /\s\-\-coff\-arg\s/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string2 = /\sCOFFLoader\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string3 = /\sShoggoth\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string4 = /\#include\s\"ShoggothEngine\.h\"/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string5 = /\/beacon_generate\.py/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string6 = /\/COFFLoader\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string7 = /\/Shoggoth\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string8 = /\/Shoggoth\.git/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string9 = /\[\+\]\sCOFF\sLoader\smode\sis\sselected\!/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string10 = /\[\+\]\sPE\sLoader\smode\sis\sselected\!/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string11 = /\[\+\]\sPolymorphic\sencryption/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string12 = /\[\+\]\sShoggoth\sengine\sis\sinitiated\!/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string13 = /\\\\stub\\\\COFFLoader\.bin/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string14 = /\\COFFLoader\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string15 = /\\DumpNParse\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string16 = /\\Shoggoth\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string17 = /\\Shoggoth\.pptx/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string18 = /\\Shoggoth\.sln/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string19 = /\\ShoggothEngine\.cpp/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string20 = /1bc3fc0ecdae8f404c33942914e6f442ea91400bdea77322b318ab576d4050a9/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string21 = /44D5BE95\-F34D\-4CC5\-846F\-C7758943B8FA/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string22 = /9cbbb2ac103af9b7940ec72a8e430427d86f5099f7a537e4fe2b72d69e05bdfd/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string23 = /\'B\'\,\'e\'\,\'a\'\,\'c\'\,\'o\'\,\'n\'/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string24 = /bin\/PELoader\.exe/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string25 = /d67630a3210bfcdd4b2fa2d48cdcdba0034710fd5ead616d9d5e4ce38e3c9809/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string26 = /frkngksl\/Shoggoth/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string27 = /Shoggoth\sdoesn\'t\ssupport\sx86\sPE\syet/ nocase ascii wide
        // Description: Shoggoth: Asmjit Based Polymorphic Encryptor
        // Reference: https://github.com/frkngksl/Shoggoth
        $string28 = /ShoggothPolyEngine\(/ nocase ascii wide

    condition:
        any of them
}
