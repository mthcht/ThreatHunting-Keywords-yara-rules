rule tor2web
{
    meta:
        description = "Detection patterns for the tool 'tor2web' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor2web"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string1 = " install tor2web" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string2 = /\st2w\.py/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string3 = "# socksport = 9050" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string4 = /\.tor2web\s/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string5 = "/bin/tor2web" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string6 = /\/etc\/init\.d\/tor/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string7 = /\/etc\/init\.d\/tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string8 = "/home/tor2web/" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string9 = /\/t2w\.py/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string10 = /\/Tor2web\-.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string11 = /\/Tor2web\-.{0,100}\.zip/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string12 = /\/tor2web\.conf/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string13 = /\/Tor2web\.git/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string14 = /\/tor2web\.js/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string15 = ">Tor2web Error: " nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string16 = "5529ff4b4c60d1cfefb02f145e149ffb166229e03aff4d8917340190753cde9e" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string17 = "87c4041617fc7010b7e20630ae48cc8c17dc84cd6fb5c330f0bc92af52baa2fa" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string18 = "a276ed1739c3380b2e918da23ddac04cc117e17e08dac219bb4f82783f9f9850" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string19 = "a6479f37d1ab80d878c949e10b1b44cd7714c87a67da40c438237af0501de51f" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string20 = "Adding GlobaLeaks PGP key to trusted APT keys" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string21 = /apt\sinstall\s.{0,100}tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string22 = /apt\-get\sinstall\s.{0,100}tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string23 = /class\sT2WRPCServer\(/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string24 = "dist-packages/tor2web/" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string25 = "from tor2web import" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string26 = "globaleaks/Tor2web" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string27 = "href=\"\"/\"\">tor2web</a>" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string28 = /http\:\/\/tor2web\./ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string29 = /https\:\/\/tor2web\./ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string30 = /info\@tor2web\.org/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string31 = /install\-tor2web\.sh/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string32 = /lists\.tor2web\.org/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string33 = "OFTC/tor2web/" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string34 = /remote_get_tor_exits_list\(/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string35 = /spawnT2W\(/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string36 = "Start the Tor2web proxy" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string37 = /Starting\stor\s\(via\ssystemctl\)/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string38 = "tor2web start" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string39 = "tor2web stop" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string40 = /tor2web\.pid/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string41 = /tor2web\.service/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string42 = "tor2web/Tor2web" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string43 = "tor2web_notification_form" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string44 = /tor2web\-cert\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string45 = /tor2web\-default\.conf/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string46 = /tor2web\-dh\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string47 = /tor2web\-globaleaks\.conf/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string48 = "tor2web-hidden" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string49 = /tor2web\-intermediate\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string50 = /tor2web\-key\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string51 = "tor2web-visible" nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string52 = /update\-rc\.d\stor2web\sdefaults/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string53 = /www\.tor2web\.org/ nocase ascii wide
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
