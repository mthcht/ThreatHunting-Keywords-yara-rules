rule ad_ldap_enum
{
    meta:
        description = "Detection patterns for the tool 'ad-ldap-enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ad-ldap-enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string1 = /\s\-p\s\'aad3b435b51404eeaad3b435b51404ee\:31d6cfe0d16ae931b73c59d7e0c089c0\'/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string2 = /\/ad\-ldap\-enum\.git/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string3 = /ad\-ldap\-enum\.py/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string4 = /ad\-ldap\-enum\-main/ nocase ascii wide
        // Description: An LDAP based Active Directory user and group enumeration tool
        // Reference: https://github.com/CroweCybersecurity/ad-ldap-enum
        $string5 = /CroweCybersecurity\/ad\-ldap\-enum/ nocase ascii wide

    condition:
        any of them
}
