rule SharpDecryptPwd
{
    meta:
        description = "Detection patterns for the tool 'SharpDecryptPwd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDecryptPwd"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string1 = /\.exe\sXmanager\s\/user\:.{0,100}\s\/sid\:.{0,100}\s\/path\:.{0,100}/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string2 = /\.exe\s\-Xmangager\s\-p\s/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string3 = /\/SharpDecryptPwd\.git/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string4 = /\\FoxmailDump\.cpp/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string5 = /\\SharpDecryptPwd\.sln/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string6 = /\\SharpDecryptPwd\\/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string7 = /\\SharpDecryptPwd\-main/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string8 = /\>SharpDecryptPwd\</ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string9 = /1824ED63\-BE4D\-4306\-919D\-9C749C1AE271/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string10 = /1f385acf11f8ea6673d7295be6492ea9913b525da25dcc037ea49ef4f86a9d58/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string11 = /2273f47d253c1974f82b9b7f9018228080e8ac41b75bba4e779fe9f918d72aa1/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string12 = /537dfda00b6ce57ca35f3da4eaac5cfc42c4180d5573673a66c4665517d0a208/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string13 = /80ed17895205205c5a769d18715cb74a623cee6a5379bb8142d2c8c533c759b2/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string14 = /RowTeam\/SharpDecryptPwd/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string15 = /SharpDecryptPwd\s/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string16 = /SharpDecryptPwd\.Commands/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string17 = /SharpDecryptPwd\.csproj/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string18 = /SharpDecryptPwd\.exe/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string19 = /SharpDecryptPwd\.exe/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string20 = /SharpDecryptPwd\.Lib/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string21 = /SharpDecryptPwd\.Properties/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string22 = /uknowsec\/SharpDecryptPwd/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string23 = /using\sSharpDecryptPwd/ nocase ascii wide
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
