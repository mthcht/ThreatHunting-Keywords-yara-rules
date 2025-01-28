rule DirCreate2System
{
    meta:
        description = "Detection patterns for the tool 'DirCreate2System' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DirCreate2System"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string1 = /\/DirCreate2System\.git/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string2 = /\/DirCreate2System\.git/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string3 = /\[\+\]\sArbitrary\sDirectory\sCreation\sto\sSYSTEM\sShell\stechnique\s\!/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string4 = /\[\+\]\sFinding\sdirectory\sto\shijack/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string5 = /\[\+\]\sPoc\sBy\s\@404death\s/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string6 = /\[\+\]\sSpawning\sSYSTEM\sshell/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string7 = /\\dircreate2system\.pdb/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string8 = /\\dircreate2system\.sln/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string9 = /\\DirCreate2System\\bin\\/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string10 = "36c88f1852f3c162bf64d973bb6f69ffb7e22503015e104716fc51eaddcbe875" nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string11 = "765C5755-DBE9-4AB5-9427-921D0E46F9F0" nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string12 = "7EE536AE-6C1D-4881-88F7-37C8F2A0CA50" nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string13 = "binderlabs/DirCreate2System" nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string14 = "binderlabs/DirCreate2System" nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string15 = /cacls\sC\:\\Windows\\System32\\wermgr\.exe\.local\s\/e\s\/g\severyone\:f/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string16 = /dir_create2system\.txt/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string17 = /dircreate2system\.cpp/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string18 = /dircreate2system\.exe/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string19 = /dircreate2system\.vcxproj/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string20 = "DirCreate2System-main" nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string21 = /dll_spawn_cmd\.cpp/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string22 = /dll_spawn_cmd\.exe/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string23 = "ebfebca063aa056d7ffd8767c7c82d66c0c1a4339eb504a8e0636280dc5b839f" nocase ascii wide
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
