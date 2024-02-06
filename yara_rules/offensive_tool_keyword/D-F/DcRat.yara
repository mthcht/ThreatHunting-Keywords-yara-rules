rule DcRat
{
    meta:
        description = "Detection patterns for the tool 'DcRat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DcRat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string1 = /\/DcRat\.git/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string2 = /\/DcRat\.sln/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string3 = /\/Ransomware\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string4 = /\\Ransomware\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string5 = /\\RemoteCamera\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string6 = /119\.45\.104\.153\:8848/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string7 = /127\.0\.0\.1\:8848/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string8 = /AsyncRAT\/DCRat/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string9 = /CN\=DcRat\sServer.{0,1000}OU\=qwqdanchun.{0,1000}O\=DcRat\sBy\sqwqdanchun/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string10 = /DcRat\s\s1\.0\.7/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string11 = /DcRat\.7z/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string12 = /DcRat\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string13 = /DcRat\.zip/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string14 = /DcRat_png\.png/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string15 = /DcRat\-main\.zip/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string16 = /https\:\/\/pastebin\.com\/raw\/fevFJe98/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string17 = /Keylogger\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string18 = /Keylogger\.pdb/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string19 = /localhost\:8848/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string20 = /Plugins\\SendFile\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string21 = /Plugins\\SendMemory\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string22 = /qwqdanchun/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string23 = /qwqdanchun\/DcRat/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string24 = /Ransomware\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string25 = /Ransomware\.pdb/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string26 = /Resources\\donut\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string27 = /ReverseProxy\.dll/ nocase ascii wide

    condition:
        any of them
}
