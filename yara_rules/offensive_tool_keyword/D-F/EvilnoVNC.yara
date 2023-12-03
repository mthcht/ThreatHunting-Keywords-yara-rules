rule EvilnoVNC
{
    meta:
        description = "Detection patterns for the tool 'EvilnoVNC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilnoVNC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string1 = /.{0,1000}\sEvilnoVNC.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string2 = /.{0,1000}\/bin\/bash\s\-c\s\"php\s\-q\s\-S\s0\.0\.0\.0:80\s\&\"\s\>\s\/dev\/null\s2\>\&1.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string3 = /.{0,1000}\/EvilnoVNC\.git.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string4 = /.{0,1000}\/EvilnoVNC\.git.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string5 = /.{0,1000}\/start\.sh\sdynamic\s.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string6 = /.{0,1000}\/tmp\/resolution\.txt.{0,1000}server\.sh.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string7 = /.{0,1000}\\EvilnoVNC.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string8 = /.{0,1000}\\EvilnoVNC\\.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string9 = /.{0,1000}\\Keylogger\.txt.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string10 = /.{0,1000}EvilnoVNC\sby\s\@JoelGMSec.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string11 = /.{0,1000}EvilnoVNC\sServer.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string12 = /.{0,1000}EvilnoVNC\-main.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string13 = /.{0,1000}EvilnoVNC\-main.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string14 = /.{0,1000}Import\sstealed\ssession\sto\sChromium\.\..{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string15 = /.{0,1000}JoelGMSec\/EvilnoVNC.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string16 = /.{0,1000}JoelGMSec\/EvilnoVNC.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string17 = /.{0,1000}keylogger\.py.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string18 = /.{0,1000}kiosk\.sh.{0,1000}startVNC\.sh.{0,1000}/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string19 = /.{0,1000}nandydark\/Linux\-keylogger.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
