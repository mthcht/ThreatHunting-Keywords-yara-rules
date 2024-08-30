rule gocrack
{
    meta:
        description = "Detection patterns for the tool 'gocrack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gocrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string1 = /\/gocrack\.git/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string2 = /\/gocrack\/\.hashcat/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string3 = /\/gocrack\/server/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string4 = /\/gocrack_server/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string5 = /\/gocrack_worker/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string6 = /\/gocrack\-1\.0\.zip/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string7 = /\/opt\/gocrack\/files\/engine/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string8 = /\/opt\/gocrack\/files\/task/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string9 = /\\gocrack\-1\.0\.zip/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string10 = /\\gocrack\-master\./ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string11 = /gocrack\@password\.crackers\.local/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string12 = /gocrack_v.{0,1000}_darwin_x64_hashcat_v3_6_0\.zip/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string13 = /gocrack_v.{0,1000}_linux_x64_hashcat_v3_6_0\.zip/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string14 = /iAmAnIndependentStrongPassswordThatNeedsToBeSecure/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string15 = /mandiant\/gocrack/ nocase ascii wide

    condition:
        any of them
}
