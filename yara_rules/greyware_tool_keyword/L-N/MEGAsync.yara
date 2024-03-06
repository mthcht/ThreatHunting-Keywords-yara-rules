rule MEGAsync
{
    meta:
        description = "Detection patterns for the tool 'MEGAsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MEGAsync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string1 = /\smegasync\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string2 = /\sMEGAsyncSetup32\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string3 = /\sMEGAsyncSetup64\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string4 = /\.api\.mega\.co\.nz/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string5 = /\.static\.mega\.co\.nz/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string6 = /\/megasync\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string7 = /\/MEGAsyncSetup32\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string8 = /\/MEGAsyncSetup64\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string9 = /\[megaapi_impl\.cpp\:/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string10 = /\[megaclient\.cpp\:/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string11 = /\\appdata\\local\\megasync\\/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string12 = /\\ContextMenuHandlers\\MEGA\s\(Context\smenu\)/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string13 = /\\CurrentVersion\\App\sPaths\\MEGAsync/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string14 = /\\CurrentVersion\\Uninstall\\MEGAsync/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string15 = /\\MEGA\sWebsite\.lnk/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string16 = /\\MEGA\sWebsite\.url/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string17 = /\\megaclient_statecache.{0,1000}\.db/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string18 = /\\megaclient_syncconfig_/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string19 = /\\megalimited\-megasync_/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string20 = /\\MEGAprivacyMEGAsync/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string21 = /\\MEGAsync\.cfg/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string22 = /\\megasync\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string23 = /\\MEGAsync\.lnk/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string24 = /\\megasync\.lock/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string25 = /\\MEGAsync\.log/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string26 = /\\megasync\.version/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string27 = /\\MEGAsyncSetup32\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string28 = /\\MEGAsyncSetup64\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string29 = /\\MEGAupdater\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string30 = /\\ProgramData\\megatmp\.M1\.txt/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string31 = /\\ProgramData\\megatmp\.M2\.txt/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string32 = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Pending\)/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string33 = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Synced\)/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string34 = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Syncing\)/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string35 = /\\Start\sMenu\\Programs\\MEGAsync\\/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string36 = /\\StartupTNotiMEGAsync\.lnk/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string37 = /\'Company\'\>Mega\sLimited\<\/Data\>/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string38 = /https\:\/\/mega\.nz\/linux\/repo\// nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string39 = /MEGAsync\sUpdate\sTask/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string40 = /MEGAsync\.exe\s\// nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string41 = /MEGASYNC\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string42 = /MEGAsync\\ShellExtX64\.dll/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string43 = /megasync\-CentOS_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string44 = /megasync\-CentOS_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string45 = /megasync\-Debian_.{0,1000}_amd64\.deb/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string46 = /megasync\-Fedora_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string47 = /megasync\-openSUSE_Leap_.{0,1000}\.x86_64\.rpm/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string48 = /megasync\-Raspbian_.{0,1000}_armhf\.deb/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string49 = /MEGAsyncSetup32_.{0,1000}_RC3\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string50 = /MEGASYNCSETUP64\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string51 = /MEGAsyncSetup64_.{0,1000}_RC3\.exe/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string52 = /MEGAsyncSetupArm64\.dmg/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string53 = /megasync\-x86_64\.pkg/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string54 = /megasync\-xUbuntu_.{0,1000}_amd64\.deb/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string55 = /\'Product\'\>MEGAsync\<\/Data\>/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string56 = /ReferrerUrl\=https\:\/\/mega\.io\// nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string57 = /\'Signature\'\>Mega\sLimited\<\/Data\>/ nocase ascii wide
        // Description: synchronize or backup your computers to MEGA
        // Reference: https://mega.io/en/desktop
        $string58 = /Windows\\System32\\Tasks\\MEGA/ nocase ascii wide

    condition:
        any of them
}
