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
        $string1 = /.{0,1000}\/DcRat\.git.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string2 = /.{0,1000}\/DcRat\.sln.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string3 = /.{0,1000}\/Ransomware\.exe.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string4 = /.{0,1000}\\Ransomware\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string5 = /.{0,1000}\\RemoteCamera\.dll.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string6 = /.{0,1000}119\.45\.104\.153:8848.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string7 = /.{0,1000}127\.0\.0\.1:8848.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string8 = /.{0,1000}AsyncRAT\/DCRat.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string9 = /.{0,1000}CN\=DcRat\sServer.{0,1000}OU\=qwqdanchun.{0,1000}O\=DcRat\sBy\sqwqdanchun.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string10 = /.{0,1000}DcRat\s\s1\.0\.7.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string11 = /.{0,1000}DcRat\.7z.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string12 = /.{0,1000}DcRat\.exe.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string13 = /.{0,1000}DcRat\.zip.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string14 = /.{0,1000}DcRat_png\.png.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string15 = /.{0,1000}DcRat\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string16 = /.{0,1000}https:\/\/pastebin\.com\/raw\/fevFJe98.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string17 = /.{0,1000}Keylogger\.exe.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string18 = /.{0,1000}Keylogger\.pdb.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string19 = /.{0,1000}localhost:8848.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string20 = /.{0,1000}Plugins\\SendFile\.dll.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string21 = /.{0,1000}Plugins\\SendMemory\.dll.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string22 = /.{0,1000}qwqdanchun.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string23 = /.{0,1000}qwqdanchun\/DcRat.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string24 = /.{0,1000}Ransomware\.dll.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string25 = /.{0,1000}Ransomware\.pdb.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string26 = /.{0,1000}Resources\\donut\.exe.{0,1000}/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string27 = /.{0,1000}ReverseProxy\.dll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
