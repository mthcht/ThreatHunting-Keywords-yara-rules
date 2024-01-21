rule SignToolEx
{
    meta:
        description = "Detection patterns for the tool 'SignToolEx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SignToolEx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string1 = /\/SignToolEx\.cpp/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string2 = /\/SignToolEx\.git/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string3 = /\/SignToolEx\.sln/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string4 = /\\SignToolEx\.cpp/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string5 = /\\SignToolEx\.sln/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string6 = /\\SignToolExDll/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string7 = /82B0EE92\-347E\-412F\-8EA2\-CBDE683EDA57/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string8 = /B8AEE3F1\-0642\-443C\-B42C\-33BADCD42365/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string9 = /hackerhouse\-opensource\/SignToolEx/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string10 = /SignToolEx\.exe/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string11 = /SignToolExHook\.dll/ nocase ascii wide
        // Description: Patching signtool.exe to accept expired certificates for code-signing
        // Reference: https://github.com/hackerhouse-opensource/SignToolEx
        $string12 = /SignToolEx\-main/ nocase ascii wide

    condition:
        any of them
}
