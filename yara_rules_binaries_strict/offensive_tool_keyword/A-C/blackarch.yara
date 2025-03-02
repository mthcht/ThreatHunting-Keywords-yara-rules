rule blackarch
{
    meta:
        description = "Detection patterns for the tool 'blackarch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blackarch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: offensive distribution - path used by a script preparation of blackarch OS
        // Reference: https://github.com/BlackArch/blackarch
        $string1 = "/tmp/blackarch" nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string2 = /au\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string3 = /blackarch\.cs\.nycu\.edu\.tw\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string4 = /blackarch\.leneveu\.fr\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string5 = /blackarch\.mirror\.digitalpacific\.com\.au\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string6 = /blackarch\.mirror\.garr\.it\/mirrors\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string7 = /blackarch\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string8 = /blackarch\.org\/blackarch\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string9 = /blackarch\.unixpeople\.org\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string10 = /ca\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string11 = /de\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string12 = /distro\.ibiblio\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string13 = /download\.nus\.edu\.sg\/mirror\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string14 = /eu\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string15 = /ftp\.cc\.uoc\.gr\/mirrors\/linux\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string16 = /ftp\.halifax\.rwth\-aachen\.de\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string17 = /ftp\.icm\.edu\.pl\/pub\/Linux\/dist\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string18 = /ftp\.kddilabs\.jp\/Linux\/packages\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string19 = /ftp\.linux\.org\.tr\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string20 = /http\:\/\/mirror\.archlinux\.no/ nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string21 = /https\:\/\/raw\.githubusercontent\.com\/BlackArch\/blackarch\/master\/mirror\/mirror\.lst/ nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string22 = /https\:\/\/www\.blackarch\.org\/blackarch\/blackarch\/lastupdate/ nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string23 = /in\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string24 = /jp\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string25 = /kr\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string26 = /md\.mirrors\.hacktegic\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string27 = /mirror\.archlinux\.tw\/BlackArch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string28 = /mirror\.cedia\.org\.ec\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string29 = /mirror\.cyberbits\.eu\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string30 = /mirror\.easyname\.at\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string31 = /mirror\.easyname\.ch\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string32 = /mirror\.maa\.albony\.in\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string33 = /mirror\.math\.princeton\.edu\/pub\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string34 = /mirror\.serverion\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string35 = /mirror\.sg\.gs\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string36 = /mirror\.sjtu\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string37 = /mirror\.team\-cymru\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string38 = /mirror\.telepoint\.bg\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string39 = /mirror\.tillo\.ch\/ftp\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string40 = /mirror\.yandex\.ru\/mirrors\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string41 = /mirror\.zetup\.net\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string42 = /mirrors\.aliyun\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string43 = /mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string44 = /mirrors\.dotsrc\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string45 = /mirrors\.gethosted\.online\/blackarch\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string46 = /mirrors\.hostico\.ro\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string47 = /mirrors\.hust\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string48 = /mirrors\.nju\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string49 = /mirrors\.ocf\.berkeley\.edu\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string50 = /mirrors\.tuna\.tsinghua\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string51 = /mirrors\.ustc\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string52 = /quantum\-mirror\.hu\/mirrors\/pub\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string53 = /repository\.su\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string54 = /sg\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string55 = /us\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string56 = /www\.ftp\.ne\.jp\/Linux\/packages\/blackarch\/.{0,100}\/os\// nocase ascii wide
        // Description: offensive distribution - url used by the OS for updates
        // Reference: https://github.com/BlackArch/blackarch
        $string57 = /www\.mirrorservice\.org\/sites\/blackarch\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
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
