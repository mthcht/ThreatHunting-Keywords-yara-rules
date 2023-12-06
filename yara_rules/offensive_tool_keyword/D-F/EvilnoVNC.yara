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
        $string1 = /\sEvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string2 = /\/bin\/bash\s\-c\s\"php\s\-q\s\-S\s0\.0\.0\.0:80\s\&\"\s\>\s\/dev\/null\s2\>\&1/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string3 = /\/EvilnoVNC\.git/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string4 = /\/EvilnoVNC\.git/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string5 = /\/start\.sh\sdynamic\s/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string6 = /\/tmp\/resolution\.txt.{0,1000}server\.sh/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string7 = /\\EvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string8 = /\\EvilnoVNC\\/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string9 = /\\Keylogger\.txt/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string10 = /EvilnoVNC\sby\s\@JoelGMSec/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string11 = /EvilnoVNC\sServer/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string12 = /EvilnoVNC\-main/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string13 = /EvilnoVNC\-main/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string14 = /Import\sstealed\ssession\sto\sChromium\.\./ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string15 = /JoelGMSec\/EvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string16 = /JoelGMSec\/EvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string17 = /keylogger\.py/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string18 = /kiosk\.sh.{0,1000}startVNC\.sh/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string19 = /nandydark\/Linux\-keylogger/ nocase ascii wide

    condition:
        any of them
}
