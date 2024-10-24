rule Adzok
{
    meta:
        description = "Detection patterns for the tool 'Adzok' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adzok"
        rule_category = "signature_keyword"

    strings:
        // Description: RAT tool - a variant of Adwind abused by TA
        // Reference: https://sourceforge.net/projects/adzok/files/Adzok_Open_v1.0.0.2.jar/download
        $string1 = /A\sVariant\sOf\sJava\/Adwind\.SN/ nocase ascii wide
        // Description: RAT tool - a variant of Adwind abused by TA
        // Reference: https://sourceforge.net/projects/adzok/files/Adzok_Open_v1.0.0.2.jar/download
        $string2 = /Adwind\!jar/ nocase ascii wide

    condition:
        any of them
}
