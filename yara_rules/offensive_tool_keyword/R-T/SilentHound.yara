rule SilentHound
{
    meta:
        description = "Detection patterns for the tool 'SilentHound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string1 = /.{0,1000}\s\-k\s\-\-kerberoast.{0,1000}/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string2 = /.{0,1000}\/SilentHound\.git.{0,1000}/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string3 = /.{0,1000}\-domain_admins\.txt.{0,1000}/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string4 = /.{0,1000}layer8secure\/SilentHound.{0,1000}/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string5 = /.{0,1000}Nick\sSwink\saka\sc0rnbread.{0,1000}/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string6 = /.{0,1000}silenthound\.py.{0,1000}/ nocase ascii wide
        // Description: Quietly enumerate an Active Directory Domain via LDAP parsing users + admins + groups...
        // Reference: https://github.com/layer8secure/SilentHound
        $string7 = /.{0,1000}SilentHound\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
