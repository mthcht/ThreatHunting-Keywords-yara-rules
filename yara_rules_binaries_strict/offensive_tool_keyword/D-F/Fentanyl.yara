rule Fentanyl
{
    meta:
        description = "Detection patterns for the tool 'Fentanyl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fentanyl"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string1 = /\scursorinit\.vbs/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string2 = /\sfenty\.py/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string3 = /\\"N\/A\s\(Likely\sPirated\)\\"/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string4 = /\#\sForce\sAdmin\:\sBypass\sAdmin\sPrivileges\?/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string5 = /\#\sInject\:\sInject\spayload\sinto\sDiscord\?/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string6 = /\#\sInjection\sURL\:\sRaw\sURL\sto\sinjection\spayload/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string7 = /\/cursorinit\.vbs/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string8 = /\/Fentanyl\.git/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string9 = /\\fenty\.py/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string10 = /\\Roblox\sCookies\.txt/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string11 = /\{os\.getlogin\(\)\}\s\|\sFentanyl/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string12 = /\>CursorSvc\</ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string13 = /2fa97965c5491fd73b586656a2a3d376013fa20918cc501f598439b85e49e244/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string14 = /70376ae9437efcd92034825528cc12f1c0e03c1a4f965aabb3377d2a19e1d4f7/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string15 = /bypassBetterDiscord\(/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string16 = /Cursors\\cursorinit\.vbs/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string17 = /dekrypted\/Fentanyl/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string18 = /Fentanyl\sstrikes\sagain\!/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string19 = /Fentanyl\/fenty\.py/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string20 = /findall\(r\\"dQw4w9WgXcQ/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string21 = /grabMinecraftCache\(/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string22 = /grabPasswords\(self\,mkp\,bname\,pname\,data\)/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string23 = /https\:\/\/.{0,100}\.gofile\.io\/uploadFile/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string24 = /https\:\/\/cdn\.discordapp\.com\/attachments\/976805447266877471\/987826721250238464\/c33cd7baf5e2abdf434c2793988ccb56\.png/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string25 = /https\:\/\/github\.com\/dekrypted\// nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string26 = /https\:\/\/youareanidiot\.cc/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string27 = /if\sos\.getlogin\(\)\sin\s\[\\"WDAGUtilityAccount\\"\,\\"Abby\\"\,\\"Peter\sWilson\\"\,\\"hmarc\\"\,\\"patex\\"\,\\"JOHN\-PC\\"\,\\"RDhJ0CNFevzX\\"\,\\"kEecfMwgj\\"\,\\"Frank\\"\,\\"8Nl0ColNQ5bq\\"/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string28 = /reagentc\s\/disable\s\>nul/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string29 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\"\s\/v\s\\"SettingsPageVisibility\\"\s\/t\sREG_SZ\s\/d\s\\"hide\:recovery\;windowsdefender\\"\s\/f\s\>nul/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string30 = /REG\sADD\sHKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\s\/v\s\\"CursorInit\\"\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string31 = /REG\sADD\sHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\s\/v\s\\"CursorInit\\"\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string32 = /schtasks\s\/create\s\/tn\s\\"CursorSvc\\"/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string33 = /SELECT\sname_on_card\,\sexpiration_month\,\sexpiration_year\,\scard_number_encrypted\sFROM\scredit_cards/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string34 = /\-\-Sharing\-this\-will\-allow\-someone\-to\-log\-in\-as\-you\-and\-to\-steal\-your\-ROBUX\-and\-items.{0,100}decrypted_cookie/ nocase ascii wide
        // Description: Stealer Malware - Steal Discord Tokens (+ Much More Info) - Steal Passwords/Cookies/History/Credit Cards/Phone Numbers and Addresses from all Browsers (Profile Support) - Steal PC Info - Steal Video Game Accounts (Adding more games + wallets and VPN's) - Low Detections - Anti VM - Sort of Fast - Startup - IP Logger
        // Reference: https://github.com/dekrypted/Fentanyl
        $string35 = /vssadmin\sdelete\sshadows\s\/all\s\/quiet\s\>nul/ nocase ascii wide
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
