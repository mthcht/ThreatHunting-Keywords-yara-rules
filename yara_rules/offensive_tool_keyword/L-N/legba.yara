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
        $string1 = /.{0,1000}\s\-\-password\swordlists\/.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string2 = /.{0,1000}\/legba\.git.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string3 = /.{0,1000}\/legba\/target\/release\/legba.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string4 = /.{0,1000}\/usr\/bin\/legba.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string5 = /.{0,1000}A\sfast\smulti\sprotocol\scredential\sbruteforcer\/sprayer\/enumerator.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string6 = /.{0,1000}docker\sbuild\s\-t\slegba\s\..{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string7 = /.{0,1000}docker\srun\slegba.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string8 = /.{0,1000}evilsocket\/legba.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string9 = /.{0,1000}legba\s.{0,1000}\s\-\-username.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string10 = /.{0,1000}legba\samqp\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string11 = /.{0,1000}legba\sdns\s.{0,1000}\-\-data\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string12 = /.{0,1000}legba\sftp\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string13 = /.{0,1000}legba\shttp\s.{0,1000}\-\-http\-payload\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string14 = /.{0,1000}legba\shttp\.basic\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string15 = /.{0,1000}legba\shttp\.enum\s.{0,1000}\-\-http.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string16 = /.{0,1000}legba\shttp\.ntlm1\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string17 = /.{0,1000}legba\shttp\.ntlm2\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string18 = /.{0,1000}legba\simap\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string19 = /.{0,1000}legba\skerberos\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string20 = /.{0,1000}legba\skerberos.{0,1000}\-\-kerberos\-realm\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string21 = /.{0,1000}legba\sldap\s.{0,1000}\-\-ldap\-domain.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string22 = /.{0,1000}legba\smongodb.{0,1000}\s\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string23 = /.{0,1000}legba\smssql\s.{0,1000}\s\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string24 = /.{0,1000}legba\smysql\s.{0,1000}\s\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string25 = /.{0,1000}legba\spgsql\s.{0,1000}\s\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string26 = /.{0,1000}legba\spop3\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string27 = /.{0,1000}legba\srdp\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string28 = /.{0,1000}legba\ssftp\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string29 = /.{0,1000}legba\ssmtp\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string30 = /.{0,1000}legba\sssh\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string31 = /.{0,1000}legba\sstomp\s.{0,1000}\-\-target.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string32 = /.{0,1000}legba\stelnet\s.{0,1000}\-\-telnet\-.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string33 = /.{0,1000}legba\svnc.{0,1000}\s\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string34 = /.{0,1000}legba\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string35 = /.{0,1000}root\scargo\snew\s\-\-bin\slegba.{0,1000}/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string36 = /.{0,1000}Simone\sMargaritelli\s\<evilsocket\@gmail\.com\>.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
