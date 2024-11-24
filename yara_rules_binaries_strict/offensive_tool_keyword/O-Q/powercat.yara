rule powercat
{
    meta:
        description = "Detection patterns for the tool 'powercat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powercat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string1 = /\s\-l\s\-p\s.{0,100}\s\-e\scmd\s\-ge/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string2 = /\spowercat\.ps1/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string3 = /\.ps1\s\-l\s\-p\s.{0,100}\s\-r\sdns\:\:\:/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string4 = /\/powercat\.git/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string5 = /\/powercat\.ps1/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string6 = /\\powercat\.ps1/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string7 = /\\powercat\-master\\/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string8 = "79acacd2433990d8fe71ee9583123240b34ae26f4913d62b796238f4a302e104" nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string9 = "besimorhino/powercat" nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string10 = "f75cca99da6b3693e3310767256f62228a4451435e4f4301fa7dc95bef9c92ff" nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string11 = "powercat -c " nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string12 = "powercat -l " nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string13 = /Write\-Verbose\s\(\\"Listening\son\s\[0\.0\.0\.0\]\sport/ nocase ascii wide
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
