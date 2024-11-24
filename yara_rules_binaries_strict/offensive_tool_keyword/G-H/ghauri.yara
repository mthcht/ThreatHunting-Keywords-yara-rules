rule ghauri
{
    meta:
        description = "Detection patterns for the tool 'ghauri' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghauri"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string1 = /\sGhauri\sis\sgoing\sto\suse\sthe\scurrent\sdatabase\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string2 = /\.py\s.{0,100}\s\-\-sql\-shell/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string3 = /\/dbms\/fingerprint\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string4 = /\/ghauri\.git/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string5 = /\/ghauri\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string6 = "/ghauri/ghauri/" nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string7 = /\\dbms\\fingerprint\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string8 = /\\ghauri\\ghauri\\/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string9 = /\\ghauri\-1.{0,100}\\ghauri\\/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string10 = "A cross-platform python based advanced sql injections detection & exploitation tool" nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string11 = /calling\sMySQL\sshell\.\sTo\squit\stype\s\'x\'\sor\s\'q\'\sand\spress\sENTER/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string12 = /Do\syou\swant\sGhauri\sset\sit\sfor\syou\s\?\s\[Y\/n\]/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string13 = /Do\syou\swant\sto\sskip\stest\spayloads\sspecific\sfor\sother\sDBMSes\?/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string14 = "ghauri currently only supports DBMS fingerprint payloads for Microsoft Access" nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string15 = "Ghauri detected connection errors multiple times" nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string16 = /Ghauri\sis\sexpecting\sdatabase\sname\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string17 = "ghauri -u " nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string18 = /ghauri\-.{0,100}\\ghauri\-/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string19 = /ghauri\.common\.config/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string20 = /ghauri\.common\.lib/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string21 = /ghauri\.common\.payloads/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string22 = /ghauri\.common\.session/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string23 = /ghauri\.common\.utils/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string24 = /ghauri\.core\.extract/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string25 = /ghauri\.core\.tests/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string26 = /ghauri\.extractor\.advance/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string27 = /ghauri\.py\s/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string28 = "ghauri_extractor" nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string29 = /ghauri\-main\.zip/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string30 = /http\:\/\/www\.site\.com\/article\.php\?id\=1/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string31 = /http\:\/\/www\.site\.com\/vuln\.php\?id\=1\s\-\-dbs/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string32 = /Nasir\sKhan\s\(r0ot\sh3x49\)/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string33 = "r0oth3x49/ghauri" nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string34 = /r0oth3x49\@gmail\.com/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string35 = /scripts\/ghauri\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string36 = /scripts\\ghauri\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string37 = "sqlmapproject/sqlmap/issues/2442" nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string38 = /testing\sfor\sSQL\sinjection\son\s\(custom\)/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string39 = /user\saborted\sduring\sDBMS\sfingerprint\./ nocase ascii wide
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
