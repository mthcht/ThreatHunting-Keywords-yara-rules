rule bettercap
{
    meta:
        description = "Detection patterns for the tool 'bettercap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bettercap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string1 = " bettercap" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string2 = /\s\-caplet\s.{0,100}\.cap/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string3 = /\s\-eval\s.{0,100}caplets\.update.{0,100}\sui\.update/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string4 = "/arp_spoof/" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string5 = "/bettercap" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string6 = /\/c2\/c2\.go/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string7 = /\/dns_grabber\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string8 = "/dns_spoof" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string9 = /\/hid_inject\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string10 = /\/hid_sniff\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string11 = "/ndp_spoof" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string12 = "/net_recon/" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string13 = /\/net_sniff\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string14 = /\/net_sniff_.{0,100}\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string15 = /\/wifi_hopping\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string16 = /arp\.spoof\son/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string17 = /arp\.spoof\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string18 = /arp\.spoof\.targets/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string19 = /arp_spoof\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string20 = "ArpSpoofer" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string21 = "bettercap " nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string22 = /bettercap\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string23 = /bettercap_\.deb/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string24 = /bettercap\-master\.zip/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string25 = /ble_recon\.go/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string26 = /dhcp6\.spoof\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string27 = /dns\.spoof\son/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string28 = /dns\.spoof\.address/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string29 = /dns\.spoof\.all/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string30 = /dns\.spoof\.domains/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string31 = /dns\.spoof\.hosts/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string32 = /dns_spoof\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string33 = /mac\.changer\son/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string34 = /ndp_spoof\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string35 = /net\.fuzz\s/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string36 = /net\.fuzz\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string37 = /net\.probe\son/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string38 = /net\.probe\son/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string39 = /net\.sniff\s/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string40 = /net\.sniff\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string41 = /net_recon\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string42 = /wifi_fake_auth\./ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string43 = "wifi_recon_handshakes" nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string44 = /net\.recon\s/ nocase ascii wide
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
