rule Tor
{
    meta:
        description = "Detection patterns for the tool 'Tor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string1 = /\/proxy\/Tor\.py/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string2 = /\/proxy\/tor_paths\.py/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string3 = /\/tor\-gencert\.exe/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string4 = /\/win\/Tor\/tor\.exe/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string5 = /r0oth3x49\/Tor\.git/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click
        // Reference: https://github.com/r0oth3x49/Tor
        $string6 = /tor_services\.py/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string7 = /TorServiceSetup/ nocase ascii wide

    condition:
        any of them
}
