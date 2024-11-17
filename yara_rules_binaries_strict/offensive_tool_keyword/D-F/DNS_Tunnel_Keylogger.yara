rule DNS_Tunnel_Keylogger
{
    meta:
        description = "Detection patterns for the tool 'DNS-Tunnel-Keylogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNS-Tunnel-Keylogger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // Reference: https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $string1 = /\.\/logger\.sh\s.{0,100}\s\&\>\s\/dev\/null\s\&\&\sexit/ nocase ascii wide
        // Description: Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // Reference: https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $string2 = /1fc325f3\-c548\-43db\-a13f\-8c460dda8381/ nocase ascii wide
        // Description: Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // Reference: https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $string3 = /4cc3c88b175e7c6c9e881707ab3a6b956c7cbcb69a5f61d417d4736f054677b4/ nocase ascii wide
        // Description: Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // Reference: https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $string4 = /920021c608185f95a4100ebec9e7c0fb4c67c1d192257ba9ac3430b2939762a3/ nocase ascii wide
        // Description: Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // Reference: https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $string5 = /c4e9806596b8e6123a595395b0efe604176dfd2e767418fe4adf69c70de557b5/ nocase ascii wide
        // Description: Keylogging server and client that uses DNS tunneling/exfiltration to transmit keystrokes
        // Reference: https://github.com/Geeoon/DNS-Tunnel-Keylogger
        $string6 = /DNS\-Tunnel\-Keylogger/ nocase ascii wide
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
