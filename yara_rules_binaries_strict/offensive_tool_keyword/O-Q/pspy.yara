rule pspy
{
    meta:
        description = "Detection patterns for the tool 'pspy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pspy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string1 = /\/bin\/pspsy/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string2 = /\/download\/v1\.1\.0\/pspy32/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string3 = /\/download\/v1\.1\.0\/pspy64/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string4 = /\/download\/v1\.2\.0\/pspy32/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string5 = /\/download\/v1\.2\.1\/pspy32/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string6 = /\/download\/v1\.2\.1\/pspy64/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string7 = /\/pspy\s\-/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string8 = /\/pspy\.git/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string9 = /\/pspy\.git/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string10 = /\/pspy\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string11 = /\/pspy\/cmd/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string12 = /\/pspy\/cmd\// nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string13 = /\/pspy\/pspy\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string14 = /\/pspy32/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string15 = /\/pspy64/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string16 = /\/psscanner\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string17 = /\/psscanner\/psscanner\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string18 = /\[\+\]\sDropping\sinto\sshell/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string19 = /\[\+\]\sStarting\spspy\snow/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string20 = /\\pspy\\pspy\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string21 = /\\psscanner\\psscanner\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string22 = /3d770299898ab069e0a7f139ed0659991feeb17f73e55b398bf982932c200ef9/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string23 = /Complete\slog\sof\spspy\s\(may\scontain\scommands\srun\sin\sthis\stest\)\:/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string24 = /docker\srun\s\-it\s\-\-rm\slocal\/pspy/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string25 = /DominicBreuker\/pspy/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string26 = /DominicBreuker\/pspy/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string27 = /pspy\s\-\sversion\:\s/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string28 = /pspy.{0,100}psscanner/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string29 = /pspy32\s\-/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string30 = /pspy64\s\-/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string31 = /pspy64\s\-p/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string32 = /pspy64\s\-r\s/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string33 = /pspy\-build\:latest/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string34 = /pspy\-development\:latest/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string35 = /pspy\-example\:latest/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string36 = /pspy\-master/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string37 = /pspy\-testing\:latest/ nocase ascii wide
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
