rule LDAPWordlistHarvester
{
    meta:
        description = "Detection patterns for the tool 'LDAPWordlistHarvester' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAPWordlistHarvester"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string1 = /.{0,1000}\/LDAPWordlistHarvester\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string2 = /.{0,1000}LDAPWordlistHarvester\.ps1.{0,1000}/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string3 = /.{0,1000}LDAPWordlistHarvester\.py.{0,1000}/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string4 = /.{0,1000}LDAPWordlistHarvester\-main.{0,1000}/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string5 = /.{0,1000}p0dalirius\/LDAPWordlistHarvester.{0,1000}/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string6 = /.{0,1000}Powershell\sLDAPWordlistHarvester.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
