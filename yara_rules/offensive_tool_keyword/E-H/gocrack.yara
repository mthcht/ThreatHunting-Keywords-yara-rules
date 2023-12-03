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
        $string1 = /.{0,1000}\/gocrack\.git.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string2 = /.{0,1000}\/gocrack\/\.hashcat.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string3 = /.{0,1000}\/gocrack\/server.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string4 = /.{0,1000}\/gocrack_server.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string5 = /.{0,1000}\/gocrack_worker.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string6 = /.{0,1000}\/gocrack\-1\.0\.zip.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string7 = /.{0,1000}\/opt\/gocrack\/files\/engine.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string8 = /.{0,1000}\/opt\/gocrack\/files\/task.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string9 = /.{0,1000}\\gocrack\-1\.0\.zip.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string10 = /.{0,1000}\\gocrack\-master\..{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string11 = /.{0,1000}gocrack\@password\.crackers\.local.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string12 = /.{0,1000}gocrack_v.{0,1000}_darwin_x64_hashcat_v3_6_0\.zip.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string13 = /.{0,1000}gocrack_v.{0,1000}_linux_x64_hashcat_v3_6_0\.zip.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string14 = /.{0,1000}iAmAnIndependentStrongPassswordThatNeedsToBeSecure.{0,1000}/ nocase ascii wide
        // Description: GoCrack is a management frontend for password cracking tools written in Go
        // Reference: https://github.com/mandiant/gocrack
        $string15 = /.{0,1000}mandiant\/gocrack.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
