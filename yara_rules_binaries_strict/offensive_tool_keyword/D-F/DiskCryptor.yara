rule DiskCryptor
{
    meta:
        description = "Detection patterns for the tool 'DiskCryptor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DiskCryptor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string1 = /\/dcrypt\.exe/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string2 = /\/dcrypt_setup\.exe/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string3 = /\/DiskCryptor\.git/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string4 = /\\dcrypt\.exe/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string5 = /\\dcrypt\.sys/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string6 = /\\DCrypt\\Bin/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string7 = /\\dcrypt_setup\.exe/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string8 = /\\Public\\dcapi\.dll/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string9 = /A38C04C7\-B172\-4897\-8471\-E3478903035E/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string10 = /A38C04C7\-B172\-4897\-8471\-E3478903035E/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string11 = /DavidXanatos\/DiskCryptor/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string12 = /dccon\.exe\s\-encrypt2/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string13 = /dcrypt_bartpe\.zip/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string14 = /dcrypt_install\.iss/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string15 = /dcrypt_setup_.{0,100}\.exe/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string16 = /dcrypt_winpe\.zip/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string17 = /DiskCryptor\sDevice\sInstallation\sDisk/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string18 = /DiskCryptor\sdriver/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string19 = /DISKCRYPTOR_MUTEX/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string20 = /DiskCryptor\-master/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string21 = /Public\\dcinst\.exe/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string22 = /SYSTEM\\CurrentControlSet\\Services\\dcrypt/ nocase ascii wide
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
