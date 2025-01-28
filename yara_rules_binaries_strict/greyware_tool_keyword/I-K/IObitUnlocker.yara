rule IObitUnlocker
{
    meta:
        description = "Detection patterns for the tool 'IObitUnlocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IObitUnlocker"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string1 = /\sIObitUnlocker\.exe/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string2 = /\/IObitUnlocker\.exe/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string3 = /\/unlocker\-setup\.exe/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string4 = /\\AppData\\Local\\Temp\\.{0,100}\\IObitUnlockerSetup/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string5 = /\\Application\sData\\IObit\\IObit\sUnlocker/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string6 = /\\Downloads\\IObitUnlockerSetup/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string7 = /\\IObit\sUnlocker\.lnk/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string8 = /\\IObitUnlocker\.dll/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string9 = /\\IObitUnlocker\.exe/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string10 = /\\IObitUnlocker\.ini/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string11 = /\\IObitUnlocker\.log/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string12 = /\\IObitUnlockerExtension\.dll/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string13 = /\\Program\sFiles\s\(x86\)\\IObit\\IObit\sUnlocker/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string14 = /\\Program\sFiles\\IObit\\IObit\sUnlocker/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string15 = /\\Uninstall\sIObit\sUnlocker\.lnk/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string16 = /\\Uninstall\sIObit\sUnlocker\.url/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string17 = /\\Unlocker\.exe/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string18 = /\\unlocker\-setup\s\(1\)\.exe/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string19 = /\\unlocker\-setup\.exe/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string20 = /\\unlocker\-setup\.tmp/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string21 = "2efdffd1cf3adab21ff760f009d8893d8c4cbcf63b2c3bfcc1139457c9cd430b" nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string22 = /http\:\/\/update\.iobit\.com\/infofiles\/iobitunlocker\.upt/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string23 = /https\:\/\/silentbreaksecurity\.com\/adaptive\-dll\-hijacking/ nocase ascii wide
        // Description: unlocking locked files on Windows systems
        // Reference: https://www.iobit.com/en/iobit-unlocker.php#
        $string24 = /IObitUnlocker\.sys/ nocase ascii wide
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
