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
        $string15 = /dcrypt_setup_.{0,1000}\.exe/ nocase ascii wide
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

    condition:
        any of them
}
