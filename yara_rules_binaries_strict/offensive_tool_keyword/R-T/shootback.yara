rule shootback
{
    meta:
        description = "Detection patterns for the tool 'shootback' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shootback"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a reverse TCP tunnel let you access target behind NAT or firewall
        // Reference: https://github.com/aploium/shootback
        $string1 = "aploium/shootback" nocase ascii wide
        // Description: a reverse TCP tunnel let you access target behind NAT or firewall
        // Reference: https://github.com/aploium/shootback
        $string2 = "bd582dca867f580de4cea00df8dafe985f7790233de90f7e962b6e6a80dd55cf" nocase ascii wide
        // Description: a reverse TCP tunnel let you access target behind NAT or firewall
        // Reference: https://github.com/aploium/shootback
        $string3 = "dd7677e9132c0e2b813bf5a5fd4b34772d0804cf36b7266a2b9d0e64075019d0" nocase ascii wide
        // Description: a reverse TCP tunnel let you access target behind NAT or firewall
        // Reference: https://github.com/aploium/shootback
        $string4 = /python3\sslaver\.py\s/ nocase ascii wide
        // Description: a reverse TCP tunnel let you access target behind NAT or firewall
        // Reference: https://github.com/aploium/shootback
        $string5 = /shadowsocks_server.{0,100}shootback_slaver/ nocase ascii wide
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
