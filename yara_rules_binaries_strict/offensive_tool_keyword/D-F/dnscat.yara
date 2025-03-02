rule dnscat
{
    meta:
        description = "Detection patterns for the tool 'dnscat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string1 = /\s\-\-dns\sdomain\=skullseclabs\.org/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string2 = /\.\/dnscat/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string3 = /\/dnscat\.c/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string4 = /\/dnscat2\.git/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string5 = /0\.0\.0\.0\:53531/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string6 = /127\.0\.0\.1\:53531/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string7 = /data\/wordlist_256\.txt/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string8 = "dnscat -"
        // Description: Welcome to dnscat2. a DNS tunnel that WON'T make you sick and kill you This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol. which is an effective tunnel out of almost every network.
        // Reference: https://github.com/iagox86/dnscat2
        $string9 = "dnscat --dns "
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string10 = "dnscat tcpcat"
        // Description: Welcome to dnscat2. a DNS tunnel that WON'T make you sick and kill you This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol. which is an effective tunnel out of almost every network.
        // Reference: https://github.com/iagox86/dnscat2
        $string11 = "dnscat"
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string12 = /dnscat2.{0,100}\.tar\.bz2/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string13 = /dnscat2\-.{0,100}\.zip/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string14 = /dnscat2\./
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string15 = "dnscat2/"
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string16 = "dnscat2-server" nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string17 = /dnscat2\-win32\.exe/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string18 = /dnsmastermind\.rb/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string19 = "localhost:53531"
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string20 = /server\=.{0,100}port\=53531/
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
