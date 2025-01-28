rule aircrack
{
    meta:
        description = "Detection patterns for the tool 'aircrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aircrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string1 = /\s\-r\sairolib\-db\s\/root\/wpa\.cap/ nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string2 = "airbase-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string3 = /aircrack\.txt/ nocase ascii wide
        // Description: WiFi security auditing tools suite.
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string4 = "Aircrack-ng" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string5 = "aircrack-ptw-" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string6 = "airdecap-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string7 = "aireplay-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string8 = "airgraph-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string9 = "airodump-ng " nocase ascii wide
        // Description: WiFi security auditing tools suite.
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string10 = "airodump-ng " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string11 = "airolib-ng airolib-db" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string12 = "airserv-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string13 = "airtun-ng -a " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string14 = "besside-ng -W -v " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string15 = /easside\-ng\s\-.{0,100}\s\-s\s127\.0\.0\.1/ nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string16 = "makeivs-ng -b " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string17 = "wesside-ng -" nocase ascii wide
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
