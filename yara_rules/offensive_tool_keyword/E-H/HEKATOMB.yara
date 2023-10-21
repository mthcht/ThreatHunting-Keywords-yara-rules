rule HEKATOMB
{
    meta:
        description = "Detection patterns for the tool 'HEKATOMB' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HEKATOMB"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string1 = /\sinstall\shekatomb/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string2 = /\.py\s.*\s\-debug\s\-dnstcp/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string3 = /hekatomb\-.*\.tar\.gz/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string4 = /hekatomb.*\-hashes\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string5 = /hekatomb\-.*\-py3\-none\-any\.whl/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string6 = /hekatomb\@thiefin\.fr/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string7 = /Processus\-Thief\/HEKATOMB/ nocase ascii wide

    condition:
        any of them
}