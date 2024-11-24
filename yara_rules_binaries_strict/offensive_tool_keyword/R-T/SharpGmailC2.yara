rule SharpGmailC2
{
    meta:
        description = "Detection patterns for the tool 'SharpGmailC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGmailC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string1 = /\sgmailC2\.exe/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string2 = /\/gmailC2\.exe/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string3 = /\/SharpGmailC2\.git/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string4 = /\\gmailC2\.exe/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string5 = /\\SharpGmailC2/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string6 = "946D24E4-201B-4D51-AF9A-3190266E0E1B" nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string7 = "CE895D82-85AA-41D9-935A-9625312D87D0" nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string8 = /GmailC2\.csproj/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string9 = /OrderFromC2\s\=\sReadEmail\(\)/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string10 = "reveng007/SharpGmailC2" nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string11 = "SharpGmailC2-main" nocase ascii wide
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
