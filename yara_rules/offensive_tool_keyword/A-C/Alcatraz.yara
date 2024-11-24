rule Alcatraz
{
    meta:
        description = "Detection patterns for the tool 'Alcatraz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alcatraz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string1 = /\sAlcatraz\.exe/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string2 = /\/Alcatraz\.exe/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string3 = /\/Alcatraz\.git/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string4 = /\/Alcatraz\/files\/.{0,1000}\/Alcatraz\.zip/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string5 = "/Alcatraz/x64" nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string6 = "/Alcatraz-gui" nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string7 = /\/obfuscator\/obfuscator\./ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string8 = /\\Alcatraz\.exe/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string9 = /Alcatraz\.sln/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string10 = /Alcatraz\.vcxproj/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string11 = "Alcatraz/obfuscator" nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string12 = /Alcatraz\-master\.zip/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string13 = /obfuscator.{0,1000}antidisassembly\./ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string14 = /obfuscator\.cpp/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string15 = "weak1337/Alcatraz" nocase ascii wide

    condition:
        any of them
}
