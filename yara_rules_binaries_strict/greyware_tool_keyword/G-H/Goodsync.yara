rule Goodsync
{
    meta:
        description = "Detection patterns for the tool 'Goodsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Goodsync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string1 = /\/GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string2 = /\\CurrentControlSet\\Services\\GsServer/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string3 = /\\DIRECTORY\\BACKGROUND\\SHELL\\GOODSYNC/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string4 = /\\GoodSync\-2.{0,100}\-.{0,100}\.log/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string5 = /\\GOODSYNC2GO\.EXE/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string6 = /\\GOODSYNC2GO\-V.{0,100}\.EXE/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string7 = /\\GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string8 = /\\gs\-runner\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string9 = /\\GS\-SERVER\.EXE/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string10 = /\\Program\sFiles\\SIBER\sSYSTEMS\\GOODSYNC\\/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string11 = /\\Siber\sSystems\\GoodSync\\/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string12 = /\\Users\\.{0,100}\\AppData\\Local\\GoodSync/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string13 = /\>GoodSync\</ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string14 = /\>gs\-runner\.exe\</ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string15 = /Copy\sNew\s.{0,100}gdrive\:\/\/www\.googleapis\.com\/GS_Sync\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string16 = /Copy\sNew\s.{0,100}sftp\:\/\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string17 = /GoodSync\sServer/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string18 = /GoodSync\-vsub\-2Go\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string19 = /mediator\.goodsync\.com/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string20 = /Program\sFiles\\Siber\sSystems\\GoodSync/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string21 = /SOFTWARE\\Siber\sSystems\\GoodSync\\Profiles/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string22 = /temp.{0,100}\\gsync\.exe/ nocase ascii wide
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
