rule expose
{
    meta:
        description = "Detection patterns for the tool 'expose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "expose"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string1 = " /usr/local/bin/expose"
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string2 = /\/expose\/database\/expose\.db/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string3 = "/expose/raw/master/builds/expose" nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string4 = "/src/expose serve "
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string5 = "beyondcode/expose" nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string6 = "docker build -t expose " nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string7 = "docker run expose " nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string8 = "expose share http://" nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string9 = /exposeConfigPath\=\/src\/config\/expose\.php/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string10 = /\'host\'\s\=\>\s\'sharedwithexpose\.com\'/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string11 = /http\:\/\/127\.0\.0\.1\:4040\/api\/logs\// nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string12 = /https\:\/\/expose\.dev\/api\/servers/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string13 = /https\:\/\/expose\.dev\/register/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
