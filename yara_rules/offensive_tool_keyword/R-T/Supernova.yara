rule Supernova
{
    meta:
        description = "Detection patterns for the tool 'Supernova' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supernova"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string1 = /.{0,1000}\.bin\s\-enc\src4\s\-lang\sc\s\-k\s3\s\-o\s.{0,1000}\.bin.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string2 = /.{0,1000}\.bin\s\-enc\src4\s\-lang\scsharp\s\-k\s9.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string3 = /.{0,1000}\.bin\s\-enc\srot\s\-lang\scsharp\s\-k\s2\s\-d.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string4 = /.{0,1000}\.bin\s\-enc\srot\s\-lang\srust\s\-k\s7.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string5 = /.{0,1000}\.bin\s\-enc\sxor\s\-lang\scsharp\s\-k\s2\s\-v\snickvourd.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string6 = /.{0,1000}\.bin\s\-enc\sxor\s\-lang\snim\s\-k\s4.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string7 = /.{0,1000}\.exe\s.{0,1000}\.bin\s\-enc\saes\s\-lang\scsharp.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string8 = /.{0,1000}\/Supernova\.exe.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string9 = /.{0,1000}\/Supernova\.git.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string10 = /.{0,1000}\[\+\]\sGenerated\sXOR\skey:\s.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string11 = /.{0,1000}\[\+\]\sSave\sencrypted\sshellcode\sto\s.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string12 = /.{0,1000}\[\+\]\sThe\sencrypted\spayload\swith\s.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string13 = /.{0,1000}\\Supernova\.exe.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string14 = /.{0,1000}build\sSupernova\.go.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string15 = /.{0,1000}nickvourd\/Supernova.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string16 = /.{0,1000}Supernova\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string17 = /.{0,1000}Supernova\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
