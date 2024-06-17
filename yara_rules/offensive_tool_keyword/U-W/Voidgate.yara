rule Voidgate
{
    meta:
        description = "Detection patterns for the tool 'Voidgate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Voidgate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string1 = /\/Voidgate\.exe/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string2 = /\/Voidgate\.git/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string3 = /\\Voidgate\.cpp/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string4 = /\\Voidgate\.exe/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string5 = /\\voidgate\-master\\/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string6 = /\\Windows\\temp\\payload\.bin/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string7 = /15bdbbebff7a58257d1cd0ade5d76877259c2b3152508f1b2534a6fcab89cb38/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string8 = /39fa3b4151fd83044106b63e95a820f4f1d769714d4f73369dba7a2187e0918b/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string9 = /bba575ec\-0c7f\-42e1\-9b59\-b7c9cca522ba/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string10 = /c06bb3f0\-cbdc\-4384\-84cf\-21b7fe6dfe01/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string11 = /vxCrypt0r\/Voidgate/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string12 = /XorEncryptPayload\.cpp/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string13 = /XorEncryptPayload\.exe/ nocase ascii wide
        // Description: bypass AV/EDR memory scanners. This can be used to hide well-known and detected shellcodes
        // Reference: https://github.com/undergroundwires/privacy.sexy
        $string14 = /XorEncryptPayload\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
