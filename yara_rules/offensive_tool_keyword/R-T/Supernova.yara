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
        $string1 = /\.bin\s\-enc\src4\s\-lang\sc\s\-k\s3\s\-o\s.{0,1000}\.bin/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string2 = /\.bin\s\-enc\src4\s\-lang\scsharp\s\-k\s9/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string3 = /\.bin\s\-enc\srot\s\-lang\scsharp\s\-k\s2\s\-d/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string4 = /\.bin\s\-enc\srot\s\-lang\srust\s\-k\s7/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string5 = /\.bin\s\-enc\sxor\s\-lang\scsharp\s\-k\s2\s\-v\snickvourd/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string6 = /\.bin\s\-enc\sxor\s\-lang\snim\s\-k\s4/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string7 = /\.exe\s.{0,1000}\.bin\s\-enc\saes\s\-lang\scsharp/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string8 = /\/Supernova\.exe/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string9 = /\/Supernova\.git/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string10 = /\[\+\]\sGenerated\sXOR\skey\:\s/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string11 = /\[\+\]\sSave\sencrypted\sshellcode\sto\s/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string12 = /\[\+\]\sThe\sencrypted\spayload\swith\s/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string13 = /\\Supernova\.exe/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string14 = /build\sSupernova\.go/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string15 = /nickvourd\/Supernova/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string16 = /Supernova\.exe\s\-/ nocase ascii wide
        // Description: securely encrypt raw shellcodes
        // Reference: https://github.com/nickvourd/Supernova
        $string17 = /Supernova\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
