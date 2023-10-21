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
        $string3 = /\.torproject\.org\/.*\/download\/tor\// nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string4 = /\/tor\-0\..*\.tar\.gz/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string5 = /deb\.torproject\.org\/torproject\.org\/.*\.asc/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string6 = /dnf\sinstall\stor\s\-y/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string7 = /install\stor\sdeb\.torproject\.org\-keyring/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string8 = /rpm\.torproject\.org\/.*public_gpg\.key/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string9 = /TorBrowser\-.*macos_ALL\.dmg/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string10 = /torbrowser\-install\-.*_ALL\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string11 = /torbrowser\-install\-win.*\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string12 = /tor\-browser\-linux.*_ALL\.tar\.xz/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string13 = /torproject/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string14 = /torproject\.org\/dist\/torbrowser\/.*\./ nocase ascii wide

    condition:
        any of them
}