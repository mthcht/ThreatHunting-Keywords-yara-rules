rule Farmer
{
    meta:
        description = "Detection patterns for the tool 'Farmer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Farmer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string1 = /\/Farmer\.git/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string2 = /\\Fertliser\.exe/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string3 = /\\Fertliser\.pdb/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string4 = /c\:\\windows\\temp\\test\.tmp\sfarmer/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string5 = /crop\.exe\s\\\\.{0,100}\\.{0,100}\.lnk\s\\\\.{0,100}\\harvest\s\\\\.{0,100}\\harvest/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string6 = /farmer\.exe\s.{0,100}\\windows\\temp/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string7 = /farmer\.exe\s8888\s60/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string8 = /Farmer\\Farmer\.csproj/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string9 = /Farmer\-main\.zip/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string10 = /Fertiliser\.exe\s\\\\/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string11 = /harvestcrop\.exe\s.{0,100}\s/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string12 = /mdsecactivebreach\/Farmer/ nocase ascii wide
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
