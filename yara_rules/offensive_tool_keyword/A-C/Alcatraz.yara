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
        $string1 = /.{0,1000}\sAlcatraz\.exe.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string2 = /.{0,1000}\/Alcatraz\.exe.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string3 = /.{0,1000}\/Alcatraz\.git.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string4 = /.{0,1000}\/Alcatraz\/files\/.{0,1000}\/Alcatraz\.zip.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string5 = /.{0,1000}\/Alcatraz\/x64.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string6 = /.{0,1000}\/Alcatraz\-gui.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string7 = /.{0,1000}\/obfuscator\/obfuscator\..{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string8 = /.{0,1000}\\Alcatraz\.exe.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string9 = /.{0,1000}Alcatraz\.sln.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string10 = /.{0,1000}Alcatraz\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string11 = /.{0,1000}Alcatraz\/obfuscator.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string12 = /.{0,1000}Alcatraz\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string13 = /.{0,1000}obfuscator.{0,1000}antidisassembly\..{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string14 = /.{0,1000}obfuscator\.cpp.{0,1000}/ nocase ascii wide
        // Description: x64 binary obfuscator
        // Reference: https://github.com/weak1337/Alcatraz
        $string15 = /.{0,1000}weak1337\/Alcatraz.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
