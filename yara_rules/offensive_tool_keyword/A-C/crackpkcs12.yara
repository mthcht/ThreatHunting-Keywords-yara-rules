rule crackpkcs12
{
    meta:
        description = "Detection patterns for the tool 'crackpkcs12' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crackpkcs12"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A multithreaded program to crack PKCS#12 files (p12 and pfx extensions) by Aestu
        // Reference: https://github.com/crackpkcs12/crackpkcs12
        $string1 = /crackpkcs12/ nocase ascii wide

    condition:
        any of them
}
