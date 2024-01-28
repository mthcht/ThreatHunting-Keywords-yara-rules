rule Lime_Crypter
{
    meta:
        description = "Detection patterns for the tool 'Lime-Crypter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lime-Crypter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string1 = /\/Lime\-Crypter\.git/ nocase ascii wide
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string2 = /\\Lime\-Crypter\.sln/ nocase ascii wide
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string3 = /\\Lime\-Crypter\\/ nocase ascii wide
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string4 = /F93C99ED\-28C9\-48C5\-BB90\-DD98F18285A6/ nocase ascii wide
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string5 = /Lime\-Crypter\.exe/ nocase ascii wide
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string6 = /NYAN\-x\-CAT\/Lime\-Crypter/ nocase ascii wide
        // Description: An obfuscation tool for .Net + Native files
        // Reference: https://github.com/NYAN-x-CAT/Lime-Crypter
        $string7 = /Release\.Lime\-Crypter\.v0\.5\.1\.exe\.zip/ nocase ascii wide

    condition:
        any of them
}
