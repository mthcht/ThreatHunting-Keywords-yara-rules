rule impacketremoteshell
{
    meta:
        description = "Detection patterns for the tool 'impacketremoteshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacketremoteshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\sremoteshell\.py/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\/RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\/RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\/remoteshell\.py/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\\\\\.\\pipe\\RemoteMaint/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\\\\\\\\\.\\\\pipe\\\\RemoteMaint/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\\RemoteMaint\.sln/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /\\RemoteMaint\.vcxproj/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /\\RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /\\RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /\\remoteshell\.py/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /037f7348a66495d6502220e15f3766aa070dd12eb40b3d08d3f855c4cd77cf7f/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /11ef63b9bc33b0da6d0b5593e55e460aa8aa8279eb9ad4b90a4dc2b722ffa6e1/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = /9e85c971331b8ad686c8d79ea81c4883d3f36a7de2071551fe5369fcf34ea3d0/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = /CE23F388\-34F5\-4543\-81D1\-91CD244C9CB1/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = /impacket\.internal_helpers/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string17 = /impacket\.smbconnection/ nocase ascii wide
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
