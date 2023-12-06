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
        $string1 = /\sbropper\.py/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string2 = /\s\-t\s127\.0\.0\.1\s\-p\s1337\s/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string3 = /\.py\s.{0,1000}\s\-\-brop\s/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string4 = /\/Bropper\.git/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string5 = /\/bropper\.py/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string6 = /bropper\.py\s/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string7 = /Bropper\-main\.zip/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string8 = /\-\-expected\sBad\s\-\-expected\-stop\sWelcome/ nocase ascii wide
        // Description: An automatic Blind ROP exploitation tool 
        // Reference: https://github.com/Hakumarachi/Bropper
        $string9 = /Hakumarachi\/Bropper/ nocase ascii wide

    condition:
        any of them
}
