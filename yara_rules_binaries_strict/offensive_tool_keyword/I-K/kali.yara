rule kali
{
    meta:
        description = "Detection patterns for the tool 'kali' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kali"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string1 = "/#kali-installer-images"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string2 = "/detail/kali-linux/"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string3 = "/home/kali"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string4 = "/kali/pool/main/"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string5 = "/kali-linux-2023"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string6 = "/kali-tools-"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string7 = "/nethunter-images/"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string8 = "/raw/kali/main/"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string9 = "/raw/kali/master/"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string10 = /\\kali\-linux\-2023/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string11 = /archive\-.{0,100}\.kali\.org\//
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string12 = /cdimage\.kali\.org\//
        // Description: Kali Linux usage with wsl - example: \system32\wsl.exe -d kali-linux /usr/sbin/adduser???
        // Reference: https://www.kali.org/
        $string13 = "-d kali-linux "
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string14 = /https\:\/\/gitlab\.com\/kalilinux\//
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string15 = /https\:\/\/kali\.download/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string16 = /hub\.docker\.com\/u\/kalilinux\//
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string17 = "--install -d kali-linux"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string18 = /kali\-.{0,100}\.deb/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string19 = /kali\-linux.{0,100}\.7z/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string20 = /kali\-linux.{0,100}\.img/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string21 = /kali\-linux.{0,100}\.iso/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string22 = /kali\-linux\-.{0,100}\.torrent/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string23 = /kali\-linux\-.{0,100}\.vmdk/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string24 = /kali\-linux\-.{0,100}\.vmwarevm/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string25 = /kali\-linux\-.{0,100}\.vmx/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string26 = /kali\-linux\-.{0,100}\-installer\-amd64\.iso/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string27 = /kali\-linux\-.{0,100}\-installer\-everything\-amd64\.iso\.torrent/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string28 = /kali\-linux\-.{0,100}\-live\-everything\-amd64\.iso\.torrent/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string29 = /kali\-linux\-.{0,100}\-raspberry\-pi\-armhf\.img\.xz/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string30 = /kali\-linux\-.{0,100}\-virtualbox\-amd64\.ova/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string31 = /kali\-linux\-.{0,100}\-vmware\-amd64\.7z/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string32 = "kalilinux/kali-rolling"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string33 = /nethunter\-.{0,100}\.torrent/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string34 = /nethunter\-.{0,100}\.zip/
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string35 = /nethunter\-.{0,100}\-oos\-ten\-kalifs\-full\.zip/
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string36 = "wsl kali-linux"
        // Description: Kali Linux usage
        // Reference: https://www.kali.org/
        $string37 = /www\.kali\.org\/get\-kali\//
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
