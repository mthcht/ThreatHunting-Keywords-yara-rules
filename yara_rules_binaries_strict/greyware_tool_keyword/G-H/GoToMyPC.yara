rule GoToMyPC
{
    meta:
        description = "Detection patterns for the tool 'GoToMyPC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoToMyPC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string1 = /\sDownloadServer\=https\:\/\/www\.gotomypc\.com\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string2 = /\sgotoopener\:\/\/launch\.getgo\.com\// nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string3 = /\sLoggingServer\=logging\.getgo\.com\sProxyHost\=/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string4 = /\\AppData\\Local\\GoToMyPC\\/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string5 = /\\AppData\\Local\\Temp\\.{0,100}\\gosetup\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string6 = /\\AppData\\Local\\Temp\\.{0,100}\\GoToOpener\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string7 = /\\Citrix\\GoToMyPc\\FileTransfer\\history/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string8 = /\\Citrix\\GoToMyPc\\GuestInvite/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string9 = /\\g2comm\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string10 = /\\g2fileh\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string11 = /\\g2host\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string12 = /\\g2mainh\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string13 = /\\g2printh\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string14 = /\\g2svc\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string15 = /\\goLoader\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string16 = /\\gosetup\[1\]\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string17 = /\\GoTo\sOpener\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string18 = /\\GoTo\\Logs\\goto\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string19 = /\\gotomon\.dll/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string20 = /\\gotomon_x64\.dll/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string21 = /\\GoToMyPC\.cab/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string22 = /\\GoToMyPC\\.{0,100}\\.{0,100}\\g2ldr\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string23 = /\\gotomypc\\g2pre\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string24 = /\\GoToMyPC\\g2svc\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string25 = /\\gotomypc_3944\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string26 = /\\GoToMyPCCrashHandler\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string27 = /\\GoToOpener\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string28 = /\\GoToOpener\[1\]\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string29 = /\\ICON_ID_GOTOMYPC/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string30 = /\\Local\\Temp\\LogMeInLogs\\GoToOpenerMsi\\/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string31 = /\\LogMeInLogs\\GoToOpenerMsi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string32 = /\\novaPDF11OEM\(x64\)\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string33 = /\\program\sfiles\s\(x86\)\\gotomypc\\g2tray\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string34 = /\\Programs\\GoToMyPC\.lnk/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string35 = /\\WOW6432Node\\Citrix\\GoToMyPc/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string36 = /\\x64\\monblanking\.sys/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string37 = "<Data>Installed GoToMyPC</Data>" nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string38 = /\=http\:\/\/www\.gotomypc\.com\/downloads\/viewer\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string39 = /api\-telemetry\.servers\.getgo\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string40 = "ApplicationName'>GoTo Opener" nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string41 = "ApplicationName'>GoToMyPC Communications" nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string42 = "ApplicationName'>GoToMyPC Host Launcher" nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string43 = "ApplicationName'>GoToMyPC Viewer" nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string44 = "cf3de8f800852490f39fdacbe74627564494235f" nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string45 = /G2MScrUtil64\.exe.{0,100}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string46 = /g2mui\.exe.{0,100}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string47 = /GoTo\sMyPC\sInstaller\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string48 = /GOTO\sMYPC\sINSTALLER\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string49 = /GoTo\sOpener\.exe\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string50 = /GOTO\sOPENER\.EXE\-.{0,100}\.pf/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string51 = /Goto\.exe.{0,100}\?type\=crashpad\-handler/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string52 = /GoToMyPC_Installation\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string53 = /GoToMyPC_Setup\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string54 = /GoToMyPCSetup_x64\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string55 = /GoToScrUtils\.exe.{0,100}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string56 = /launcher\-rest\-new\.live\.corecollab\.ucc\-prod\.eva\.goto\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string57 = /novaPDF11PrinterDriver\(x64\)\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string58 = /PollServer\spoll\.gotomypc\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string59 = "ServiceName'>GoToMyPC" nocase ascii wide
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
