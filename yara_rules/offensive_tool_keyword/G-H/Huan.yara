rule Huan
{
    meta:
        description = "Detection patterns for the tool 'Huan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Huan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently. it works on 64 bit PE files.
        // Reference: https://github.com/frkngksl/Huan
        $string1 = /\/huan\.exe\s/ nocase ascii wide
        // Description: Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently. it works on 64 bit PE files.
        // Reference: https://github.com/frkngksl/Huan
        $string2 = /\/HuanLoader\// nocase ascii wide
        // Description: Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently. it works on 64 bit PE files.
        // Reference: https://github.com/frkngksl/Huan
        $string3 = /\\huan\.exe\s/ nocase ascii wide
        // Description: Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently. it works on 64 bit PE files.
        // Reference: https://github.com/frkngksl/Huan
        $string4 = /huan\.exe\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently. it works on 64 bit PE files.
        // Reference: https://github.com/frkngksl/Huan
        $string5 = /Huan\.sln/ nocase ascii wide
        // Description: Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently. it works on 64 bit PE files.
        // Reference: https://github.com/frkngksl/Huan
        $string6 = /Huan\.vcxproj/ nocase ascii wide
        // Description: Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently. it works on 64 bit PE files.
        // Reference: https://github.com/frkngksl/Huan
        $string7 = /HuanLoader\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
