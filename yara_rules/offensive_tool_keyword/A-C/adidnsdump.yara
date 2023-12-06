rule adidnsdump
{
    meta:
        description = "Detection patterns for the tool 'adidnsdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adidnsdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones. similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
        // Reference: https://github.com/dirkjanm/adidnsdump
        $string1 = /adidnsdump/ nocase ascii wide

    condition:
        any of them
}
