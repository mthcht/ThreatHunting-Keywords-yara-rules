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
        $string2 = /\.py\s.{0,1000}\s\-debug\s\-dnstcp/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string3 = /\/exported_credentials\.csv/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string4 = /\[\+\]\sConnnecting\sto\sall\scomputers\sand\stry\sto\sget\sdpapi\sblobs\sand\smaster\skey\sfiles/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string5 = /\[\+\]\sScanning\scomputers\slist\son\sSMB\sport\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string6 = /\\exported_credentials\.csv/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string7 = /ed9d3ee993fe0a36bb7a7fce3940112ea29eccca58165738a758c58a3fe0ae54/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string8 = /hekatomb\s\-hashes\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string9 = /hekatomb\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string10 = /hekatomb.{0,1000}\-hashes\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string11 = /hekatomb\-.{0,1000}\-py3\-none\-any\.whl/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string12 = /hekatomb\.ad_ldap/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string13 = /hekatomb\@thiefin\.fr/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string14 = /it\swill\sextract\sdomain\scontroller\sprivate\skey\sthrough\sRPC\suses\sit\sto\sdecrypt\sall\scredentials/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string15 = /New\scredentials\sfound\sfor\suser\s.{0,1000}\son\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string16 = /pacman\s\-S\shekatomb/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string17 = /poetry\srun\shekatomb/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string18 = /Processus\-Thief\/HEKATOMB/ nocase ascii wide

    condition:
        any of them
}
