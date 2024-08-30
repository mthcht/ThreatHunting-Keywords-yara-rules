rule POC
{
    meta:
        description = "Detection patterns for the tool 'POC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "POC"
        rule_category = "signature_keyword"

    strings:
        // Description: CVE-2024-6768: Improper validation of specified quantity in input produces an unrecoverable state in CLFS.sys causing a BSoD
        // Reference: https://github.com/fortra/CVE-2024-6768
        $string1 = /Trojan\:Win64\/CryptInject\.XY\!MTB/ nocase ascii wide

    condition:
        any of them
}
