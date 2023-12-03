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
        $string1 = /.{0,1000}\s\-o\sffuf\.csv.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string2 = /.{0,1000}\/ffuf\.git.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string3 = /.{0,1000}\/ffuf\/ffufrc.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string4 = /.{0,1000}cd\sffuf.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string5 = /.{0,1000}ffuf\s.{0,1000}\-input\-cmd.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string6 = /.{0,1000}ffuf\s.{0,1000}\-u\shttp.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string7 = /.{0,1000}ffuf\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string8 = /.{0,1000}ffuf\s\-w\s.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string9 = /.{0,1000}ffuf\.exe.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string10 = /.{0,1000}ffuf\/ffuf.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string11 = /.{0,1000}ffuf_.{0,1000}_freebsd_.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string12 = /.{0,1000}ffuf_.{0,1000}_linux_.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string13 = /.{0,1000}ffuf_.{0,1000}_macOS_.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string14 = /.{0,1000}ffuf_.{0,1000}_openbsd_.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string15 = /.{0,1000}ffuf_.{0,1000}_windows_.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string16 = /.{0,1000}ffuf\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string17 = /.{0,1000}fuff\s.{0,1000}\-input\-shell.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string18 = /.{0,1000}fuff\s.{0,1000}\-scraperfile.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string19 = /.{0,1000}fuff\s.{0,1000}\-scrapers.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string20 = /.{0,1000}https:\/\/ffuf\.io\.fi.{0,1000}/ nocase ascii wide
        // Description: Fast web fuzzer written in Go
        // Reference: https://github.com/ffuf/ffuf
        $string21 = /.{0,1000}https:\/\/ffuf\.io\/FUZZ.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
