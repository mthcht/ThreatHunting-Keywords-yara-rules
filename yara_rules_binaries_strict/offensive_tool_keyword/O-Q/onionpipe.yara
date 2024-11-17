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
        $string6 = /\/onionpipe\/releases\/latest/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string7 = /\/onionpipe\:main/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string8 = /\/usr\/share\/keyrings\/tor\-archive\-keyring/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string9 = /build_onionpipe\.bash/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string10 = /build_tor_darwin\.bash/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string11 = /build_tor_debian\.bash/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string12 = /cmars\/onionpipe/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string13 = /dsbqrprgkqqifztta6h3w7i2htjhnq7d3qkh3c7gvc35e66rrcv66did\.onion/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string14 = /failed\sto\sshut\sdown\sTor\s\-\-\spossible\sbug\sin\sbine/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string15 = /make\sonionpipe/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string16 = /onionpipe\s\-\-/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string17 = /onionpipe\s.{0,100}\.onion\:/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string18 = /onionpipe\s.{0,100}\:.{0,100}\~/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string19 = /onionpipe\s\/run\// nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string20 = /onionpipe\s8000/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string21 = /onionpipe\sclient\snew\s/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string22 = /onionpipe\/secrets/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string23 = /onionpipe\/tor/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string24 = /onionpipe\-darwin\-amd64\-static/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string25 = /onionpipe\-linux\-amd64\-static/ nocase ascii wide
        // Description: onionpipe forwards ports on the local host to remote Onion addresses as Tor hidden services and vice-versa.
        // Reference: https://github.com/cmars/onionpipe
        $string26 = /sd6aq2r6jvuoeisrudq7jbqufjh6nck5buuzjmgalicgwrobgfj4lkqd\.onion/ nocase ascii wide
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
