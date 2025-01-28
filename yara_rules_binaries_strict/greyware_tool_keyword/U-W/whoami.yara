rule whoami
{
    meta:
        description = "Detection patterns for the tool 'whoami' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whoami"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: N/A
        $string1 = " -exec bypass -nop -c whoami" nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string2 = "whoami /all" nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string3 = "whoami /domain" nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string4 = "whoami /groups" nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string5 = "whoami /priv" nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string6 = "whoami" nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string7 = /whoami\.exe.{0,100}\s\/groups/ nocase ascii wide
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
