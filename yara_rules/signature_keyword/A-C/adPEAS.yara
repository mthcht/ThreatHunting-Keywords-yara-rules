rule adPEAS
{
    meta:
        description = "Detection patterns for the tool 'adPEAS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adPEAS"
        rule_category = "signature_keyword"

    strings:
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string1 = "ATK/Adpeas-A" nocase ascii wide

    condition:
        any of them
}
