rule GMSAPasswordReader
{
    meta:
        description = "Detection patterns for the tool 'GMSAPasswordReader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GMSAPasswordReader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string1 = /\/GMSAPasswordReader\.git/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string2 = /GMSAPasswordReader\.exe/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string3 = /GMSAPasswordReader\-master/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string4 = /rvazarkar\/GMSAPasswordReader/ nocase ascii wide

    condition:
        any of them
}
