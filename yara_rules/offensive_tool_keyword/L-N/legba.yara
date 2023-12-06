rule legba
{
    meta:
        description = "Detection patterns for the tool 'legba' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "legba"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string1 = /\s\-\-password\swordlists\/.{0,1000}\.txt/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string2 = /\/legba\.git/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string3 = /\/legba\/target\/release\/legba/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string4 = /\/usr\/bin\/legba/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string5 = /A\sfast\smulti\sprotocol\scredential\sbruteforcer\/sprayer\/enumerator/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string6 = /docker\sbuild\s\-t\slegba\s\./ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string7 = /docker\srun\slegba/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string8 = /evilsocket\/legba/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string9 = /legba\s.{0,1000}\s\-\-username/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string10 = /legba\samqp\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string11 = /legba\sdns\s.{0,1000}\-\-data\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string12 = /legba\sftp\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string13 = /legba\shttp\s.{0,1000}\-\-http\-payload\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string14 = /legba\shttp\.basic\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string15 = /legba\shttp\.enum\s.{0,1000}\-\-http/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string16 = /legba\shttp\.ntlm1\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string17 = /legba\shttp\.ntlm2\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string18 = /legba\simap\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string19 = /legba\skerberos\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string20 = /legba\skerberos.{0,1000}\-\-kerberos\-realm\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string21 = /legba\sldap\s.{0,1000}\-\-ldap\-domain/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string22 = /legba\smongodb.{0,1000}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string23 = /legba\smssql\s.{0,1000}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string24 = /legba\smysql\s.{0,1000}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string25 = /legba\spgsql\s.{0,1000}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string26 = /legba\spop3\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string27 = /legba\srdp\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string28 = /legba\ssftp\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string29 = /legba\ssmtp\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string30 = /legba\sssh\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string31 = /legba\sstomp\s.{0,1000}\-\-target/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string32 = /legba\stelnet\s.{0,1000}\-\-telnet\-/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string33 = /legba\svnc.{0,1000}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string34 = /legba\-main\.zip/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string35 = /root\scargo\snew\s\-\-bin\slegba/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string36 = /Simone\sMargaritelli\s\<evilsocket\@gmail\.com\>/ nocase ascii wide

    condition:
        any of them
}
