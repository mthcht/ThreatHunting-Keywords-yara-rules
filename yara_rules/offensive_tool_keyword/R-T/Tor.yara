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
        $string1 = /.{0,1000}\/proxy\/Tor\.py.{0,1000}/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string2 = /.{0,1000}\/proxy\/tor_paths\.py.{0,1000}/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string3 = /.{0,1000}\/tor\-gencert\.exe.{0,1000}/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string4 = /.{0,1000}\/win\/Tor\/tor\.exe.{0,1000}/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string5 = /.{0,1000}r0oth3x49\/Tor\.git.{0,1000}/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click
        // Reference: https://github.com/r0oth3x49/Tor
        $string6 = /.{0,1000}tor_services\.py.{0,1000}/ nocase ascii wide
        // Description: Tor is a python based module for using tor proxy/network services on windows - osx - linux with just one click.
        // Reference: https://github.com/r0oth3x49/Tor
        $string7 = /.{0,1000}TorServiceSetup.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
