rule rdp
{
    meta:
        description = "Detection patterns for the tool 'rdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdp"
        rule_category = "signature_keyword"

    strings:
        // Description: rdp file received in emails - abused by attackers
        // Reference: https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files
        $string1 = /Backdoor\:Script\/HustleCon\.A/ nocase ascii wide

    condition:
        any of them
}
