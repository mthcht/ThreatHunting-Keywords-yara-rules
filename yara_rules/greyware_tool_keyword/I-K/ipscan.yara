rule ipscan
{
    meta:
        description = "Detection patterns for the tool 'ipscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ipscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string1 = /.{0,1000}\s\-jar\sipscan\.exe.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string2 = /.{0,1000}\/AppFiles\/ipscan\.exe.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string3 = /.{0,1000}\/ipscan\.exe.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string4 = /.{0,1000}\/ipscan_.{0,1000}_amd64\.deb.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string5 = /.{0,1000}\/ipscan2\-binary\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string6 = /.{0,1000}\/ipscan\-any\-.{0,1000}\.jar.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string7 = /.{0,1000}\\Angry\sIP\sScanner\.app.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string8 = /.{0,1000}\\ipscan\-.{0,1000}\-setup\.exe.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string9 = /.{0,1000}\\ipscan221\.exe.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string10 = /.{0,1000}\\ipscan\-crash\.txt.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string11 = /.{0,1000}ipscan\s1.{0,1000}\.255.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string12 = /.{0,1000}ipscan\s10\..{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string13 = /.{0,1000}ipscan\s172\..{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string14 = /.{0,1000}ipscan\s192\.168\..{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string15 = /.{0,1000}ipscan\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string16 = /.{0,1000}ipscan\-win64\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string17 = /.{0,1000}MacOS\/ipscan\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
