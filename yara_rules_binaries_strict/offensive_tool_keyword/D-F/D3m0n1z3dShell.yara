rule D3m0n1z3dShell
{
    meta:
        description = "Detection patterns for the tool 'D3m0n1z3dShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D3m0n1z3dShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string1 = /\.bashrc\spersistence\ssetup\ssuccessfully/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string2 = /\/chisel_x32/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string3 = /\/chisel_x64/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string4 = /\/D3m0n1z3dShell\.git/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string5 = /\/D3m0n1z3dShell\/archive\// nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string6 = /\/deepce\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string7 = /\/install_locutus\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string8 = /\/linpeas\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string9 = /\/tmp\/borg_d3monized/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string10 = /\/tmp\/tmpfolder\/pingoor\.c/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string11 = /\/tmp\/tmpfolder\/pingoor\.h/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string12 = /\[D3m0niz3d\]\~\#/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string13 = /\\chisel_x32/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string14 = /\\chisel_x64/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string15 = /addPreloadToPrivesc/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string16 = /bashRCPersistence/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string17 = /D3m0n1z3dShell\-main/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string18 = /deepce\.sh\s\-e\s/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string19 = /demonizedshell\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string20 = /demonizedshell_static\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string21 = /discovery_port_scan/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string22 = /dumpcreds.{0,100}mimipenguin/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string23 = /I2lmbmRlZiBQSU5HT09SCiNkZWZpbmUgUElOR09PUgoKI2RlZmluZSBTRVJWRVJJUCAiM/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string24 = /icmpBackdoor/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string25 = /implant_rootkit\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string26 = /lkmRootkitmodified/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string27 = /MatheuZSecurity\/D3m0n1z3dShell/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string28 = /mimipenguin\.py/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string29 = /mimipenguin\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string30 = /MotdPersistence/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string31 = /pwd\|passwd\|password\|PASSWD\|PASSWORD\|dbuser\|dbpass\|pass/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string32 = /su_brute_user_num/ nocase ascii wide
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
