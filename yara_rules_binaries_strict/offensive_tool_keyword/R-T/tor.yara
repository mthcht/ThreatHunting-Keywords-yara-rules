rule tor
{
    meta:
        description = "Detection patterns for the tool 'tor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string1 = "/bin/torify"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string2 = /\/dpkg\/info\/tor\.list/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string3 = /\/etc\/cron\.weekly\/tor/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string4 = "/etc/default/tor"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string5 = /\/etc\/init\.d\/tor/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string6 = "/etc/sv/tor/log"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string7 = /\/etc\/tor\/.{0,100}\.conf/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string8 = /\/invocation\:tor\.service/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string9 = /\/multi\-user\.target\.wants\/tor\.service/
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string10 = /\/proxy\/Tor\.py/
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string11 = /\/proxy\/tor_paths\.py/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string12 = "/run/tor/socks"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string13 = /\/run\/tor\/tor\.pid/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string14 = "/tor -mindepth 1 -maxdepth 1 -type f "
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string15 = "/tor/torrc"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string16 = "/tor-archive-keyring"
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string17 = /\/tor\-gencert\.exe/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string18 = /\/tor\-geoipdb\.list/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string19 = /\/torsocks\.conf/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string20 = /\/torsocks\.list/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string21 = "/usr/sbin/tor"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string22 = "/var/lib/tor/"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string23 = "/var/log/tor/"
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string24 = /\/win\/Tor\/tor\.exe/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string25 = /127\.0\.0\.1\:9050/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string26 = "apt install tor "
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string27 = /deb\.torproject\.org\/torproject\.org\//
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string28 = /deb\.torproject\.org\-keyring/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string29 = "debian-tor:x"
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string30 = /r0oth3x49\/Tor\.git/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string31 = /tor\@default\.service/
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click
        // Reference: https://github.com/r0oth3x49/Tor
        $string32 = /tor_services\.py/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string33 = "tor2socks"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string34 = "tor-geoipdb:all"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string35 = "tor-geoipdb:amd64"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string36 = "torify curl "
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string37 = "torify ghaur "
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string38 = "torify nuclei "
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string39 = "torify sqlmap "
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string40 = "TorServiceSetup"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string41 = "torsocks:amd64"
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
