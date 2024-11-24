rule wireshark
{
    meta:
        description = "Detection patterns for the tool 'wireshark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wireshark"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string1 = "bin/wireshark" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string2 = /dl\.wireshark\.org/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string3 = "dumpcap -" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string4 = "install tshark" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string5 = "libwireshark16" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string6 = "libwireshark-data" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string7 = "libwireshark-dev" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string8 = "libwiretap13" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string9 = "--no-promiscuous-mode" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string10 = "sharkd -a tcp:" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string11 = /tshark\s.{0,100}\-i\s/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string12 = "tshark -f " nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string13 = "tshark -Q" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string14 = "tshark -r " nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string15 = /tshark.{0,100}\.deb/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string16 = "Wireshark" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string17 = /wireshark.{0,100}\.deb/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string18 = /Wireshark.{0,100}\.dmg/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string19 = /wireshark\-.{0,100}\.tar\.xz/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string20 = "wireshark-common" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string21 = "wireshark-dev" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string22 = "wireshark-gtk" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string23 = "WiresharkPortable64" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string24 = "wireshark-qt" nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string25 = /Wireshark\-win.{0,100}\.exe/ nocase ascii wide
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
