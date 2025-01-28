rule onionpipe
{
    meta:
        description = "Detection patterns for the tool 'onionpipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onionpipe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string1 = /\stor\sdeb\.torproject\.org\-keyring/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string2 = /\.onion\:31337/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string3 = /\.onion\:8000/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string4 = /\.onion\:81/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string5 = /\/onionpipe\.git/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string6 = "/onionpipe/releases/latest" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string7 = "/onionpipe:main"
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string8 = "/usr/share/keyrings/tor-archive-keyring"
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string9 = /build_onionpipe\.bash/
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string10 = /build_tor_darwin\.bash/
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string11 = /build_tor_debian\.bash/
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string12 = "cmars/onionpipe" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string13 = /dsbqrprgkqqifztta6h3w7i2htjhnq7d3qkh3c7gvc35e66rrcv66did\.onion/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string14 = "failed to shut down Tor -- possible bug in bine" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string15 = "make onionpipe" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string16 = "onionpipe --" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string17 = /onionpipe\s.{0,1000}\.onion\:/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string18 = /onionpipe\s.{0,1000}\:.{0,1000}\~/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string19 = "onionpipe /run/" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string20 = "onionpipe 8000" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string21 = "onionpipe client new " nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string22 = "onionpipe/secrets" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string23 = "onionpipe/tor" nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string24 = "onionpipe-darwin-amd64-static"
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string25 = "onionpipe-linux-amd64-static"
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string26 = /sd6aq2r6jvuoeisrudq7jbqufjh6nck5buuzjmgalicgwrobgfj4lkqd\.onion/ nocase ascii wide

    condition:
        any of them
}
