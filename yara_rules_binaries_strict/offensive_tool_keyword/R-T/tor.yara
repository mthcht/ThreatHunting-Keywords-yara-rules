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
        $string1 = " tor:amd64 " nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string2 = "/bin/torify" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string3 = /\/dpkg\/info\/tor\.list/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string4 = /\/etc\/cron\.weekly\/tor/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string5 = "/etc/default/tor" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string6 = /\/etc\/init\.d\/tor/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string7 = "/etc/sv/tor/log" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string8 = /\/etc\/tor\/.{0,100}\.conf/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string9 = /\/invocation\:tor\.service/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string10 = /\/multi\-user\.target\.wants\/tor\.service/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string11 = /\/proxy\/Tor\.py/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string12 = /\/proxy\/tor_paths\.py/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string13 = "/run/tor/socks" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string14 = /\/run\/tor\/tor\.pid/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string15 = "/tor -mindepth 1 -maxdepth 1 -type f " nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string16 = "/tor/torrc" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string17 = "/tor-archive-keyring" nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string18 = /\/tor\-gencert\.exe/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string19 = /\/tor\-geoipdb\.list/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string20 = /\/torsocks\.conf/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string21 = /\/torsocks\.list/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string22 = "/usr/sbin/tor" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string23 = "/var/lib/tor/" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string24 = "/var/log/tor/" nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string25 = /\/win\/Tor\/tor\.exe/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string26 = /127\.0\.0\.1\:9050/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string27 = "apt install tor " nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string28 = /deb\.torproject\.org\/torproject\.org\// nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string29 = /deb\.torproject\.org\-keyring/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string30 = "debian-tor:x" nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string31 = /r0oth3x49\/Tor\.git/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string32 = /tor\@default\.service/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click
        // Reference: https://github.com/r0oth3x49/Tor
        $string33 = /tor_services\.py/ nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string34 = "tor-geoipdb:all" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string35 = "tor-geoipdb:amd64" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string36 = "torify curl " nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string37 = "torify ghaur " nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string38 = "torify nuclei " nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string39 = "torify sqlmap " nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string40 = "TorServiceSetup" nocase ascii wide
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string41 = "torsocks:amd64" nocase ascii wide
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
