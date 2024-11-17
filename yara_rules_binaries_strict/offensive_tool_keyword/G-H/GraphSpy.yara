rule GraphSpy
{
    meta:
        description = "Detection patterns for the tool 'GraphSpy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphSpy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string1 = /\sGraphSpy\.py/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string2 = /\/GraphSpy\.git/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string3 = /\/GraphSpy\.py/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string4 = /\\GraphSpy\.py/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string5 = /\\GraphSpy\-master/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string6 = /\]\sStarting\sGraphSpy\.\sOpen\sin\syour\sbrowser\sby\sgoing\sto\sthe\surl\sdisplayed\sbelow\./ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string7 = /app\.config\[\'graph_spy_db_folder\'\]/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string8 = /app\.config\[\'graph_spy_db_path\'\]/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string9 = /f0037d99bc3119fc613d304af20599e8c791b1c99208d5d452a01738777f7b49/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string10 = /graphspy\s\-i\s/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string11 = /GraphSpy\.GraphSpy\:main/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string12 = /graphspy\.py\s\-i\s/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string13 = /RedByte1337\/GraphSpy/ nocase ascii wide
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
