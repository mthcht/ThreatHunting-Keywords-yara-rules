rule sshtunnel
{
    meta:
        description = "Detection patterns for the tool 'sshtunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string1 = " install -c conda-forge sshtunnel" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string2 = " -m sshtunnel " nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string3 = /\ssshtunnel\.py/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string4 = /\sSSHTunnelForwarder\(/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string5 = "/sshtunnel -"
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string6 = /\/sshtunnel\.git/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string7 = /\/sshtunnel\.py/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string8 = "/sshtunnel/tarball/" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string9 = "/sshtunnel/zipball/" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string10 = /\\sshtunnel\.py/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string11 = "c89b4490de04897b1c16e5dae1c10ef10e60c56294bd4ca45d1669f5dcb6f9e3" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string12 = /Creating\sSSHTunnelForwarder.{0,100}paramiko/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string13 = "easy_install sshtunnel" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string14 = "from sshtunnel import " nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string15 = "from sshtunnel import SSHTunnelForwarder" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string16 = "import sshtunnel" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string17 = "pahaz/sshtunnel" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string18 = "pip install sshtunnel" nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string19 = /sshtunnel\.readthedocs\.io/ nocase ascii wide
        // Description: SSH tunnels to remote server
        // Reference: https://github.com/pahaz/sshtunnel
        $string20 = /sshtunnel\.readthedocs\.org/ nocase ascii wide
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
