rule GMSAPasswordReader
{
    meta:
        description = "Detection patterns for the tool 'GMSAPasswordReader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GMSAPasswordReader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\/GMSAPasswordReader\./ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string2 = /\/GMSAPasswordReader\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /\\GMSAPasswordReader\./ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = /\>GMSAPasswordReader\</ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string5 = /GMSAPasswordReader\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string6 = /GMSAPasswordReader\.exe/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string7 = /GMSAPasswordReader\-master/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string8 = /Retrieve\spassword\sfor\sthe\saccount\sarobbins\sin\sthe\sdomain\stestlab/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string9 = /Retrieve\spassword\sfor\sthe\saccount\sjkohler\sin\syour\scurrent\sdomain/ nocase ascii wide
        // Description: Reads the password blob from a GMSA account using LDAP and parses the values into hashes for re-use.
        // Reference: https://github.com/rvazarkar/GMSAPasswordReader
        $string10 = /rvazarkar\/GMSAPasswordReader/ nocase ascii wide

    condition:
        any of them
}
