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
        $string1 = /\s\-\-password\swordlists\/.{0,100}\.txt/ nocase ascii wide
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
        $string9 = /evilsocket\@gmail\.com/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string10 = /legba\s.{0,100}\s\-\-username/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string11 = /legba\samqp\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string12 = /legba\sdns\s.{0,100}\-\-data\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string13 = /legba\sftp\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string14 = /legba\shttp\s.{0,100}\-\-http\-payload\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string15 = /legba\shttp\.basic\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string16 = /legba\shttp\.enum\s.{0,100}\-\-http/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string17 = /legba\shttp\.ntlm1\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string18 = /legba\shttp\.ntlm2\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string19 = /legba\simap\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string20 = /legba\skerberos\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string21 = /legba\skerberos.{0,100}\-\-kerberos\-realm\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string22 = /legba\sldap\s.{0,100}\-\-ldap\-domain/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string23 = /legba\smongodb.{0,100}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string24 = /legba\smssql\s.{0,100}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string25 = /legba\smysql\s.{0,100}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string26 = /legba\spgsql\s.{0,100}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string27 = /legba\spop3\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string28 = /legba\srdp\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string29 = /legba\ssftp\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string30 = /legba\ssmtp\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string31 = /legba\sssh\s.{0,100}\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string32 = /legba\sstomp\s.{0,100}\-\-target/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string33 = /legba\stelnet\s.{0,100}\-\-telnet\-/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string34 = /legba\svnc.{0,100}\s\-\-target\s/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string35 = /legba\-main\.zip/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string36 = /root\scargo\snew\s\-\-bin\slegba/ nocase ascii wide
        // Description: A multiprotocol credentials bruteforcer / password sprayer and enumerator
        // Reference: https://github.com/evilsocket/legba
        $string37 = /Simone\sMargaritelli\s\<evilsocket\@gmail\.com\>/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
