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
        $string1 = /.{0,1000}\/GMSAPasswordReader\.git.{0,1000}/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string2 = /.{0,1000}GMSAPasswordReader\.exe.{0,1000}/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string3 = /.{0,1000}GMSAPasswordReader\-master.{0,1000}/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string4 = /.{0,1000}rvazarkar\/GMSAPasswordReader.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
