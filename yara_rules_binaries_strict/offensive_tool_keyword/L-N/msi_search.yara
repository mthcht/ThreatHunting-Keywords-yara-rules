rule msi_search
{
    meta:
        description = "Detection patterns for the tool 'msi-search' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msi-search"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string1 = /\/msi_search\.ps1/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string2 = /\/msi\-search\.git/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string3 = /\\msi_search\.c/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string4 = /\\msi_search\.exe/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string5 = /\\msi_search\.ps1/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string6 = /\\msi_search\.x64\.o/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string7 = /\\msi_search\.x86\.o/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string8 = "mandiant/msi-search" nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string9 = /msi\-search\-main\.zip/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string10 = "Search cached MSI files in C:/Windows/Installer/" nocase ascii wide
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
