rule BlackShades
{
    meta:
        description = "Detection patterns for the tool 'BlackShades' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlackShades"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string1 = /\\"keylog\.php\\"/ nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string2 = /\/keylog\.php/ nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string3 = ">Blackshades NET<" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string4 = "2720ade6e794942ef6b2340db083e2e8ae392ca5ca08e71aae5329865b13e814" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string5 = "4b7a6d90bd88298bc472e3f092cb4d1f60b46f5530b0e4d3b85dd236cbd17b92" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string6 = "6f3476967a8ef65e491229af8ddfb6a9958a346f151b9bce48122e1a04b97539" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string7 = "71b9c3db10f12ee563c0668b04171ca99e79ab1cd09911bc79f061d6d3da544d" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string8 = "Blackshades Database Viewer" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string9 = "Blackshades NET Web Server" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string10 = "e024e14ccb85b8c59cfc10ee2d9aa867c85e036382363fd8581c97ecaaf10fb4" nocase ascii wide
        // Description: remote access trojan (RAT) used by attackers to gain unauthorized control over a victim's computer
        // Reference: https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/BlackShades
        $string11 = /http\:\/\/bshades\.eu/ nocase ascii wide
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
