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
        $string1 = /.{0,1000}\sinstall\shekatomb.{0,1000}/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string2 = /.{0,1000}\.py\s.{0,1000}\s\-debug\s\-dnstcp.{0,1000}/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string3 = /.{0,1000}hekatomb\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string4 = /.{0,1000}hekatomb.{0,1000}\-hashes\s.{0,1000}/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string5 = /.{0,1000}hekatomb\-.{0,1000}\-py3\-none\-any\.whl.{0,1000}/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string6 = /.{0,1000}hekatomb\@thiefin\.fr.{0,1000}/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string7 = /.{0,1000}Processus\-Thief\/HEKATOMB.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
