rule Blank_Grabber
{
    meta:
        description = "Detection patterns for the tool 'Blank-Grabber' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Blank-Grabber"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string1 = /\sBlankOBF\.py/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string2 = /\/Blank\%20Grabber\/Extras\/hash/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string3 = /\/Blank\.Grabber\.zip/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string4 = /\/Blank\-Grabber\#download/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string5 = /\/Blank\-Grabber\.git/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string6 = /\/BlankOBF\.py/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string7 = /\\Blank\.Grabber\.zip/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string8 = /\\BlankOBF\.py/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string9 = /\\rarreg\.key/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string10 = /1e83e7eb564b39cd4d600a3b9a906a2b59bbae26320b15b5065638ad267cc3cb/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string11 = /5a0bd791d08f5f9871a1b2fa7f1aea81d0aeb90c7df95fe0534d3faac1847e74/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string12 = /\-\-add\-data\srarreg\.key/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string13 = /Blank\sGrabber\s\[Builder\]\"/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string14 = /Blank\sGrabber\s\[Fake\sError\sBuilder\]\"/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string15 = /Blank\sGrabber\s\[File\sPumper\]\"/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string16 = /Blank\-c\/Blank\-Grabber/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string17 = /c97df5d25ea1e9ed5b95606adc492cfb6d4fe97e2a538fcaef0ea66f1a239e64/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string18 = /Grabbed\sby\sBlank\sGrabber\s\|\s/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string19 = /import\sBlankOBF/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string20 = /Injecting\sbackdoor\sinto\sdiscord/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string21 = /ping\slocalhost\s\-n\s3\s\>\sNUL\s\&\&\sdel\s\/A\sH\s\/F\s/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string22 = /powershell\sGet\-ItemPropertyValue\s\-Path\s\{\}\:SOFTWARE\\\\Roblox\\\\RobloxStudioBrowser\\\\roblox\.com\s\-Name\s\.ROBLOSECURITY/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string23 = /powershell\sGet\-ItemPropertyValue\s\-Path\s\'HKLM\:SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\SoftwareProtectionPlatform\'\s\-Name\sBackupProductKeyDefault/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string24 = /SELECT\shost_key\,\sname\,\spath\,\sencrypted_value\,\sexpires_utc\sFROM\scookies/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string25 = /SELECT\sorigin_url\,\susername_value\,\spassword_value\sFROM\slogins/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string26 = /Stealer\sfinished\sits\swork/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string27 = /Stealing\sbrowser\sdata/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string28 = /Stealing\scrypto\swallets/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string29 = /Stealing\sdiscord\stokens/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string30 = /Stealing\sEpic\ssession/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string31 = /Stealing\sGrowtopia\ssession/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string32 = /Stealing\sMinecraft\srelated\sfiles/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string33 = /Stealing\sRoblox\scookies/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string34 = /Stealing\sSteam\ssession/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string35 = /Stealing\ssystem\sinformation/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string36 = /Stealing\stelegram\ssessions/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string37 = /Stealing\sUplay\ssession/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string38 = /Trying\sto\sbypass\sUAC\s\(Application\swill\srestart\)/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string39 = /Trying\sto\sdisable\sdefender/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string40 = /Trying\sto\sexclude\sbound\sfile\sfrom\sdefender/ nocase ascii wide
        // Description: Stealer with multiple functions
        // Reference: https://github.com/Blank-c/Blank-Grabber
        $string41 = /Trying\sto\sexclude\sthe\sfile\sfrom\sWindows\sdefender/ nocase ascii wide

    condition:
        any of them
}
