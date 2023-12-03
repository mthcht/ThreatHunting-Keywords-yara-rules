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
        $string1 = /.{0,1000}\s\.\/tor\.keyring\s.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string2 = /.{0,1000}\s\.\\tor\.keyring\s.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string3 = /.{0,1000}\s\-\-DataDirectory\s.{0,1000}\s\-\-CookieAuthentication\s.{0,1000}\s\-\-DisableNetwork\s.{0,1000}\s\-\-hush\s\-\-SocksPort\s.{0,1000}\s\-f\s.{0,1000}\s\-\-ControlPort\s.{0,1000}\s\-\-ControlPortWriteToFile\s.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string4 = /.{0,1000}\.torproject\.org\/.{0,1000}\/download\/tor\/.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string5 = /.{0,1000}\/tor\-0\..{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string6 = /.{0,1000}\/torbrowser\-install\-.{0,1000}\.exe\s\s.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string7 = /.{0,1000}\/tor\-browser\-linux.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string8 = /.{0,1000}\/tor\-browser\-osx64.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string9 = /.{0,1000}\/tor\-browser\-win32.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string10 = /.{0,1000}\/tor\-browser\-win64.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string11 = /.{0,1000}\/tor\-package\-archive\/.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string12 = /.{0,1000}\\AppData\\Local\\Temp\\tor\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string13 = /.{0,1000}\\Temp\\tor\\control\-port\-.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string14 = /.{0,1000}\\Temp\\tor\\torrc\-.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string15 = /.{0,1000}\\tor\.exe.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string16 = /.{0,1000}\\torbrowser\-install\-.{0,1000}\.exe\s\s.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string17 = /.{0,1000}\\tor\-browser\-win32.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string18 = /.{0,1000}\\tor\-browser\-win64.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string19 = /.{0,1000}archive\.torproject\.org.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string20 = /.{0,1000}deb\.torproject\.org\/torproject\.org\/.{0,1000}\.asc.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string21 = /.{0,1000}dnf\sinstall\stor\s\-y.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string22 = /.{0,1000}install\stor\sdeb\.torproject\.org\-keyring.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string23 = /.{0,1000}rpm\.torproject\.org\/.{0,1000}public_gpg\.key.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string24 = /.{0,1000}taskkill\s\/IM\stor\.exe\s\/F.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string25 = /.{0,1000}tor\s\-\-DataDirectory\s.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string26 = /.{0,1000}TorBrowser\-.{0,1000}macos_ALL\.dmg.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string27 = /.{0,1000}torbrowser\-install\-.{0,1000}_ALL\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string28 = /.{0,1000}torbrowser\-install\-win.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string29 = /.{0,1000}tor\-browser\-linux.{0,1000}_ALL\.tar\.xz.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string30 = /.{0,1000}torproject.{0,1000}/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string31 = /.{0,1000}torproject\.org\/dist\/torbrowser\/.{0,1000}\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
