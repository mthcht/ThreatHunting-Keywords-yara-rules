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
        $string1 = /\sdnsdump\.py/ nocase ascii wide
        // Description: By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones. similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
        // Reference: https://github.com/dirkjanm/adidnsdump
        $string2 = /\.py\s\-u\s.{0,1000}\s\?print\-zones\s/ nocase ascii wide
        // Description: By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones. similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
        // Reference: https://github.com/dirkjanm/adidnsdump
        $string3 = /\/adidnsdump\.git/ nocase ascii wide
        // Description: By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones. similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
        // Reference: https://github.com/dirkjanm/adidnsdump
        $string4 = /\/dnsdump\.py/ nocase ascii wide
        // Description: By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones. similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
        // Reference: https://github.com/dirkjanm/adidnsdump
        $string5 = /\\dnsdump\.py/ nocase ascii wide
        // Description: By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones. similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
        // Reference: https://github.com/dirkjanm/adidnsdump
        $string6 = /adidnsdump/ nocase ascii wide
        // Description: By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones. similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
        // Reference: https://github.com/dirkjanm/adidnsdump
        $string7 = /dirkjanm\/adidnsdump/ nocase ascii wide

    condition:
        any of them
}
