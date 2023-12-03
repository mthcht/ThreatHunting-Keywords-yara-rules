rule bropper
{
    meta:
        description = "Detection patterns for the tool 'bropper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bropper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string1 = /.{0,1000}\sbropper\.py.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string2 = /.{0,1000}\s\-t\s127\.0\.0\.1\s\-p\s1337\s.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string3 = /.{0,1000}\.py\s.{0,1000}\s\-\-brop\s.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string4 = /.{0,1000}\/Bropper\.git.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string5 = /.{0,1000}\/bropper\.py.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string6 = /.{0,1000}bropper\.py\s.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string7 = /.{0,1000}Bropper\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string8 = /.{0,1000}\-\-expected\sBad\s\-\-expected\-stop\sWelcome.{0,1000}/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string9 = /.{0,1000}Hakumarachi\/Bropper.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
