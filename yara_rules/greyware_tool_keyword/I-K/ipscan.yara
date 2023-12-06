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
        $string1 = /\s\-jar\sipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string2 = /\/AppFiles\/ipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string3 = /\/ipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string4 = /\/ipscan_.{0,1000}_amd64\.deb/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string5 = /\/ipscan2\-binary\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string6 = /\/ipscan\-any\-.{0,1000}\.jar/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string7 = /\\Angry\sIP\sScanner\.app/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string8 = /\\ipscan\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string9 = /\\ipscan221\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string10 = /\\ipscan\-crash\.txt/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string11 = /ipscan\s1.{0,1000}\.255/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string12 = /ipscan\s10\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string13 = /ipscan\s172\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string14 = /ipscan\s192\.168\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string15 = /ipscan\.exe\s\-/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string16 = /ipscan\-win64\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string17 = /MacOS\/ipscan\s\-/ nocase ascii wide

    condition:
        any of them
}
