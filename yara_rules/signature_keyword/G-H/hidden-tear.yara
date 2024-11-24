rule hidden_tear
{
    meta:
        description = "Detection patterns for the tool 'hidden-tear' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hidden-tear"
        rule_category = "signature_keyword"

    strings:
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string1 = "hiddentear/msil" nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string2 = "MSIL/Hiddentear" nocase ascii wide

    condition:
        any of them
}
