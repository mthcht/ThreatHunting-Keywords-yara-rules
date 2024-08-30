rule TDSKiller
{
    meta:
        description = "Detection patterns for the tool 'TDSKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TDSKiller"
        rule_category = "signature_keyword"

    strings:
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string1 = /Application\.RiskTool\.TDSSKiller\.A/ nocase ascii wide

    condition:
        any of them
}
