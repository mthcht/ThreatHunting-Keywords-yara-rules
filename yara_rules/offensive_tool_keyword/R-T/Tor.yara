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
        $string2 = "/bin/torify"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string3 = /\/dpkg\/info\/tor\.list/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string4 = /\/etc\/cron\.weekly\/tor/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string5 = "/etc/default/tor"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string6 = /\/etc\/init\.d\/tor/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string7 = "/etc/sv/tor/log"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string8 = /\/etc\/tor\/.{0,1000}\.conf/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string9 = /\/invocation\:tor\.service/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string10 = /\/multi\-user\.target\.wants\/tor\.service/
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string11 = /\/proxy\/Tor\.py/
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string12 = /\/proxy\/tor_paths\.py/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string13 = "/run/tor/socks"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string14 = /\/run\/tor\/tor\.pid/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string15 = "/tor -mindepth 1 -maxdepth 1 -type f "
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string16 = "/tor/torrc"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string17 = "/tor-archive-keyring"
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string18 = /\/tor\-gencert\.exe/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string19 = /\/tor\-geoipdb\.list/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string20 = /\/torsocks\.conf/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string21 = /\/torsocks\.list/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string22 = "/usr/sbin/tor"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string23 = "/var/lib/tor/"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string24 = "/var/log/tor/"
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string25 = /\/win\/Tor\/tor\.exe/
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
        $string31 = /r0oth3x49\/Tor\.git/
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string32 = /tor\@default\.service/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click
        // Reference: https://github.com/r0oth3x49/Tor
        $string33 = /tor_services\.py/
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
        $string40 = "TorServiceSetup"
        // Description: used for anonymous communication and web browsing. It is designed to protect users' privacy and freedom by preventing surveillance or traffic analysis. Abused by attacker for defense evasion, contacting C2 and data exfiltration
        // Reference: https://deb.torproject.org/torproject.org/
        $string41 = "torsocks:amd64" nocase ascii wide

    condition:
        any of them
}
