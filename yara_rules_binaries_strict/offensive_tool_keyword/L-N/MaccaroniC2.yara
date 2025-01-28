rule MaccaroniC2
{
    meta:
        description = "Detection patterns for the tool 'MaccaroniC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaccaroniC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string1 = /\/asyncssh_server\.py/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string2 = "/MaccaroniC2" nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string3 = /\\MaccaroniC2/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string4 = /127\.0\.0\.1\:8022/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string5 = /127\.0\.0\.1\:9050/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string6 = /asyncssh_commander\.py\s/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string7 = /asyncssh_commander\.py/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string8 = "localhost:8022" nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string9 = /MaccaroniC2\.git/ nocase ascii wide
        // Description: A proof-of-concept Command & Control framework that utilizes the powerful AsyncSSH Python library which provides an asynchronous client and server implementation of the SSHv2 protocol and use PyNgrok wrapper for ngrok integration.
        // Reference: https://github.com/CalfCrusher/MaccaroniC2
        $string10 = /socks5h\:\/\/127\.0\.0\.1\:9050/ nocase ascii wide
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
