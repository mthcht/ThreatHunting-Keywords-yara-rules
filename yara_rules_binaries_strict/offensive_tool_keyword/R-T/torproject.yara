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
        $string1 = /\s\.\/tor\.keyring\s/
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string2 = /\s\.\\tor\.keyring\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string3 = /\s\-\-DataDirectory\s.{0,100}\s\-\-CookieAuthentication\s.{0,100}\s\-\-DisableNetwork\s.{0,100}\s\-\-hush\s\-\-SocksPort\s.{0,100}\s\-f\s.{0,100}\s\-\-ControlPort\s.{0,100}\s\-\-ControlPortWriteToFile\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string4 = /\.torproject\.org\/.{0,100}\/download\/tor\// nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string5 = /\/tor\-0\..{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string6 = /\/torbrowser\-install\-.{0,100}\.exe\s\s/
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string7 = /\/tor\-browser\-linux.{0,100}\./
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string8 = /\/tor\-browser\-osx64.{0,100}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string9 = /\/tor\-browser\-win32.{0,100}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string10 = /\/tor\-browser\-win64.{0,100}\./ nocase ascii wide
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
        $string16 = /\\torbrowser\-install\-.{0,100}\.exe\s\s/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string17 = /\\tor\-browser\-win32.{0,100}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string18 = /\\tor\-browser\-win64.{0,100}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string19 = /archive\.torproject\.org/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string20 = /deb\.torproject\.org\/torproject\.org\/.{0,100}\.asc/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string21 = "dnf install tor -y"
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string22 = /http\:\/\/.{0,100}\.onion/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string23 = /http\:\/\/.{0,100}\.tor2web/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string24 = /http\:\/\/.{0,100}\.torlink/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string25 = /https\:\/\/.{0,100}\.onion/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string26 = /https\:\/\/.{0,100}\.tor2web/ nocase ascii wide
        // Description: Detects suspicious TOR usage which anonymizes user's web traffic through a relay network
        // Reference: torproject.org
        $string27 = /https\:\/\/.{0,100}\.torlink/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string28 = /install\stor\sdeb\.torproject\.org\-keyring/
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string29 = /rpm\.torproject\.org\/.{0,100}public_gpg\.key/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string30 = /taskkill\s\/IM\stor\.exe\s\/F/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string31 = "tor --DataDirectory " nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string32 = /TorBrowser\-.{0,100}macos_ALL\.dmg/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string33 = /torbrowser\-install\-.{0,100}_ALL\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string34 = /torbrowser\-install\-win.{0,100}\.exe/ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string35 = "torbrowser-install-win64" nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string36 = /tor\-browser\-linux.{0,100}_ALL\.tar\.xz/
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string37 = /torproject\.org\/dist\/torbrowser\/.{0,100}\./ nocase ascii wide
        // Description: Browse Privately. Explore Freely. Defend yourself against tracking and surveillance. Circumvent censorship.
        // Reference: torproject.org
        $string38 = /torproject\.org\/download\/download\// nocase ascii wide
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
