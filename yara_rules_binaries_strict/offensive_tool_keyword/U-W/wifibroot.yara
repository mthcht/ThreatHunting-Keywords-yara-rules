rule wifibroot
{
    meta:
        description = "Detection patterns for the tool 'wifibroot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifibroot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string1 = "/WiFiBroot" nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string2 = /\-\-mode\s3\s\-\-type\shandshake\s\-\-essid\s.{0,100}\s\-\-verbose\s\-d\sdicts\/.{0,100}\s\-\-read\s.{0,100}\.cap/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string3 = /\-\-mode\s3\s\-\-type\spmkid\s\-\-verbose\s\-d\sdicts\/.{0,100}\s\-\-read\s.{0,100}\.txt/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string4 = /wifibroot\.py/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string5 = /wireless\/captures\.py/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string6 = /wireless\/cracker\.py/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string7 = /wireless\/pmkid\.py/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string8 = /wireless\/sniper\.py/ nocase ascii wide
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
