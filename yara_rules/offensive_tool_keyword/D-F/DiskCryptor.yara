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
        $string1 = /.{0,1000}\/dcrypt\.exe.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string2 = /.{0,1000}\/dcrypt_setup\.exe.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string3 = /.{0,1000}\/DiskCryptor\.git.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string4 = /.{0,1000}\\dcrypt\.exe.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string5 = /.{0,1000}\\dcrypt\.sys.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string6 = /.{0,1000}\\DCrypt\\Bin.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string7 = /.{0,1000}\\dcrypt_setup\.exe.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string8 = /.{0,1000}\\Public\\dcapi\.dll.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string9 = /.{0,1000}A38C04C7\-B172\-4897\-8471\-E3478903035E.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string10 = /.{0,1000}A38C04C7\-B172\-4897\-8471\-E3478903035E.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string11 = /.{0,1000}DavidXanatos\/DiskCryptor.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string12 = /.{0,1000}dccon\.exe\s\-encrypt2.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string13 = /.{0,1000}dcrypt_bartpe\.zip.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string14 = /.{0,1000}dcrypt_install\.iss.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string15 = /.{0,1000}dcrypt_setup_.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string16 = /.{0,1000}dcrypt_winpe\.zip.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string17 = /.{0,1000}DiskCryptor\sDevice\sInstallation\sDisk.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string18 = /.{0,1000}DiskCryptor\sdriver.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string19 = /.{0,1000}DISKCRYPTOR_MUTEX.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string20 = /.{0,1000}DiskCryptor\-master.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string21 = /.{0,1000}Public\\dcinst\.exe.{0,1000}/ nocase ascii wide
        // Description: DiskCryptor is an open source encryption solution that offers encryption of all disk partitions including system partitions
        // Reference: https://github.com/DavidXanatos/DiskCryptor
        $string22 = /.{0,1000}SYSTEM\\CurrentControlSet\\Services\\dcrypt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
