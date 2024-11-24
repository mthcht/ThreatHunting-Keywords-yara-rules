rule torproject
{
    meta:
        description = "Detection patterns for the tool 'torproject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "torproject"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string1 = /\s\.\/tor\.keyring\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string2 = /\s\.\\tor\.keyring\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string3 = /\s\-\-DataDirectory\s.{0,1000}\s\-\-CookieAuthentication\s.{0,1000}\s\-\-DisableNetwork\s.{0,1000}\s\-\-hush\s\-\-SocksPort\s.{0,1000}\s\-f\s.{0,1000}\s\-\-ControlPort\s.{0,1000}\s\-\-ControlPortWriteToFile\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string4 = /\.torproject\.org\/.{0,1000}\/download\/tor\// nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string5 = /\/tor\-0\..{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string6 = /\/torbrowser\-install\-.{0,1000}\.exe\s\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string7 = /\/tor\-browser\-linux.{0,1000}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string8 = /\/tor\-browser\-osx64.{0,1000}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string9 = /\/tor\-browser\-win32.{0,1000}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string10 = /\/tor\-browser\-win64.{0,1000}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string11 = "/tor-package-archive/" nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string12 = /\\AppData\\Local\\Temp\\tor\s\-\-/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string13 = /\\Temp\\tor\\control\-port\-/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string14 = /\\Temp\\tor\\torrc\-/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string15 = /\\tor\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string16 = /\\torbrowser\-install\-.{0,1000}\.exe\s\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string17 = /\\tor\-browser\-win32.{0,1000}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string18 = /\\tor\-browser\-win64.{0,1000}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string19 = /archive\.torproject\.org/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string20 = /deb\.torproject\.org\/torproject\.org\/.{0,1000}\.asc/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string21 = "dnf install tor -y" nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string22 = /http\:\/\/.{0,1000}\.onion/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string23 = /http\:\/\/.{0,1000}\.tor2web/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string24 = /http\:\/\/.{0,1000}\.torlink/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string25 = /https\:\/\/.{0,1000}\.onion/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string26 = /https\:\/\/.{0,1000}\.tor2web/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string27 = /https\:\/\/.{0,1000}\.torlink/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string28 = /install\stor\sdeb\.torproject\.org\-keyring/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string29 = /rpm\.torproject\.org\/.{0,1000}public_gpg\.key/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string30 = /taskkill\s\/IM\stor\.exe\s\/F/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string31 = "tor --DataDirectory " nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string32 = /TorBrowser\-.{0,1000}macos_ALL\.dmg/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string33 = /torbrowser\-install\-.{0,1000}_ALL\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string34 = /torbrowser\-install\-win.{0,1000}\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string35 = "torbrowser-install-win64" nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string36 = /tor\-browser\-linux.{0,1000}_ALL\.tar\.xz/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string37 = /torproject\.org\/dist\/torbrowser\/.{0,1000}\./ nocase ascii wide

    condition:
        any of them
}
