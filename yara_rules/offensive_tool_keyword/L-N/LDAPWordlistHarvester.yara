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
        $string1 = /\/LDAPWordlistHarvester\.git/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string2 = /LDAPWordlistHarvester\.ps1/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string3 = /LDAPWordlistHarvester\.py/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string4 = /LDAPWordlistHarvester\-main/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string5 = /p0dalirius\/LDAPWordlistHarvester/ nocase ascii wide
        // Description: A tool to generate a wordlist from the information present in LDAP in order to crack passwords of domain accounts.
        // Reference: https://github.com/p0dalirius/LDAPWordlistHarvester
        $string6 = /Powershell\sLDAPWordlistHarvester/ nocase ascii wide

    condition:
        any of them
}
