rule SniffPass
{
    meta:
        description = "Detection patterns for the tool 'SniffPass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffPass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string1 = /\/password_sniffer\.html/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string2 = "/sniffpass-x64" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string3 = /\\SniffPass\.chm/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string4 = /\\SniffPass\.pdb/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string5 = /\\sniffpass\-x64/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string6 = ">Password Sniffer<" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string7 = ">SniffPass<" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string8 = "1df8e073ca89d026578464b0da9748194ef62c826dea4af9848ef23b3ddf1785" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string9 = "c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string10 = /http\:\/\/www\.nirsoft\.net\/password_test/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string11 = "PacketSnifferClass1" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string12 = /SniffPass\.exe/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string13 = /sniffpass\-x64\.zip/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string14 = /Software\\NirSoft\\SniffPass/ nocase ascii wide
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
