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
        $string11 = /\/tor\-package\-archive\// nocase ascii wide
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
        $string21 = /dnf\sinstall\stor\s\-y/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string22 = /install\stor\sdeb\.torproject\.org\-keyring/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string23 = /rpm\.torproject\.org\/.{0,1000}public_gpg\.key/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string24 = /taskkill\s\/IM\stor\.exe\s\/F/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string25 = /tor\s\-\-DataDirectory\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string26 = /TorBrowser\-.{0,1000}macos_ALL\.dmg/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string27 = /torbrowser\-install\-.{0,1000}_ALL\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string28 = /torbrowser\-install\-win.{0,1000}\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string29 = /tor\-browser\-linux.{0,1000}_ALL\.tar\.xz/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string30 = /torproject/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string31 = /torproject\.org\/dist\/torbrowser\/.{0,1000}\./ nocase ascii wide

    condition:
        any of them
}
