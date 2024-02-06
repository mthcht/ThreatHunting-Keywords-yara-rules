rule ffuf
{
    meta:
        description = "Detection patterns for the tool 'ffuf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ffuf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string1 = /\s\-o\sffuf\.csv/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string2 = /\/ffuf\.git/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string3 = /\/ffuf\/ffufrc/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string4 = /cd\sffuf/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string5 = /ffuf\s.{0,1000}\-input\-cmd/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string6 = /ffuf\s.{0,1000}\-u\shttp/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string7 = /ffuf\s\-c\s/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string8 = /ffuf\s\-w\s/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string9 = /ffuf\.exe/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string10 = /ffuf\/ffuf/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string11 = /ffuf_.{0,1000}_freebsd_.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string12 = /ffuf_.{0,1000}_linux_.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string13 = /ffuf_.{0,1000}_macOS_.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string14 = /ffuf_.{0,1000}_openbsd_.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string15 = /ffuf_.{0,1000}_windows_.{0,1000}\.zip/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string16 = /ffuf\-master\.zip/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string17 = /fuff\s.{0,1000}\-input\-shell/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string18 = /fuff\s.{0,1000}\-scraperfile/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string19 = /fuff\s.{0,1000}\-scrapers/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string20 = /https\:\/\/ffuf\.io\.fi/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string21 = /https\:\/\/ffuf\.io\/FUZZ/ nocase ascii wide

    condition:
        any of them
}
