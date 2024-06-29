rule DEDSEC_RANSOMWARE
{
    meta:
        description = "Detection patterns for the tool 'DEDSEC-RANSOMWARE' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DEDSEC-RANSOMWARE"
        rule_category = "signature_keyword"

    strings:
        // Description: dedsec ransomware
        // Reference: https://github.com/xelroth/DEDSEC-RANSOMWARE
        $string1 = /Ransom\:Win32\/Dedsec/ nocase ascii wide

    condition:
        any of them
}
