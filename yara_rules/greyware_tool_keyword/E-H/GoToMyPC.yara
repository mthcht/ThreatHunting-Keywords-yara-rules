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
        $string1 = /\sDownloadServer\=https:\/\/www\.gotomypc\.com\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string2 = /\sgotoopener:\/\/launch\.getgo\.com\// nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string3 = /\sLoggingServer\=logging\.getgo\.com\sProxyHost\=/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string4 = /\\AppData\\Local\\GoToMyPC\\/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string5 = /\\AppData\\Local\\Temp\\.{0,1000}\\gosetup\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string6 = /\\AppData\\Local\\Temp\\.{0,1000}\\GoToOpener\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string7 = /\\Citrix\\GoToMyPc\\FileTransfer\\history/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string8 = /\\Citrix\\GoToMyPc\\GuestInvite/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string9 = /\\goLoader\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string10 = /\\gosetup\[1\]\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string11 = /\\GoTo\sOpener\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string12 = /\\GoTo\\Logs\\goto\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string13 = /\\gotomon\.dll/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string14 = /\\gotomon_x64\.dll/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string15 = /\\GoToMyPC\.cab/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string16 = /\\GoToMyPC\\.{0,1000}\\.{0,1000}\\g2ldr\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string17 = /\\gotomypc\\g2pre\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string18 = /\\GoToMyPC\\g2svc\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string19 = /\\gotomypc_3944\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string20 = /\\GoToMyPCCrashHandler\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string21 = /\\GoToOpener\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string22 = /\\GoToOpener\[1\]\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string23 = /\\ICON_ID_GOTOMYPC/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string24 = /\\Local\\Temp\\LogMeInLogs\\GoToOpenerMsi\\/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string25 = /\\LogMeInLogs\\GoToOpenerMsi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string26 = /\\novaPDF11OEM\(x64\)\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string27 = /\\program\sfiles\s\(x86\)\\gotomypc\\g2tray\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string28 = /\\Programs\\GoToMyPC\.lnk/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string29 = /\\WOW6432Node\\Citrix\\GoToMyPc/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string30 = /\\x64\\monblanking\.sys/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string31 = /\<Data\>Installed\sGoToMyPC\<\/Data\>/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string32 = /\=http:\/\/www\.gotomypc\.com\/downloads\/viewer\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string33 = /api\-telemetry\.servers\.getgo\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string34 = /ApplicationName\'\>GoTo\sOpener/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string35 = /ApplicationName\'\>GoToMyPC\sCommunications/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string36 = /ApplicationName\'\>GoToMyPC\sHost\sLauncher/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string37 = /ApplicationName\'\>GoToMyPC\sViewer/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string38 = /cf3de8f800852490f39fdacbe74627564494235f/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string39 = /G2MScrUtil64\.exe.{0,1000}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string40 = /g2mui\.exe.{0,1000}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string41 = /GoTo\sMyPC\sInstaller\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string42 = /GOTO\sMYPC\sINSTALLER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string43 = /GoTo\sOpener\.exe\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string44 = /GOTO\sOPENER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string45 = /Goto\.exe.{0,1000}\?type\=crashpad\-handler/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string46 = /GoToMyPC_Installation\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string47 = /GoToMyPC_Setup\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string48 = /GoToMyPCSetup_x64\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string49 = /GoToScrUtils\.exe.{0,1000}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string50 = /launcher\-rest\-new\.live\.corecollab\.ucc\-prod\.eva\.goto\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string51 = /novaPDF11PrinterDriver\(x64\)\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string52 = /PollServer\spoll\.gotomypc\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string53 = /ServiceName\'\>GoToMyPC/ nocase ascii wide

    condition:
        any of them
}
