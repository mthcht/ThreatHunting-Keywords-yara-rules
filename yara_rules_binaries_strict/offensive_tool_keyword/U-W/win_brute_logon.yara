rule win_brute_logon
{
    meta:
        description = "Detection patterns for the tool 'win-brute-logon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "win-brute-logon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string1 = /\sdarkcodersc\s/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string2 = /\.exe\s\-v\s\-u\s.{0,100}\s\-w\s10k\-most\-common\.txt/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string3 = /\/DarkCoderSc\// nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string4 = /\/Passwords\/Common\-Credentials\/10k\-most\-common\.txt/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string5 = /\/WinBruteLogon/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string6 = /\/win\-brute\-logon/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string7 = /\/win\-brute\-logon\.git/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string8 = /2FE6C1D0\-0538\-48DB\-B4FA\-55F0296A5150/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string9 = /net\slocalgroup\sadministrators\sdarkcodersc\s\/add/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string10 = /net\slocalgroup\sguests\sGuestUser\s\/add/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string11 = /net\slocalgroup\susers\sGuestUser\s\/delete/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string12 = /net\suser\sdarkcodersc\s\/add/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string13 = /net\suser\sdarkcodersc\strousers/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string14 = /net\suser\sGuestUser\s\/add/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string15 = /net\suser\sHackMe\s/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string16 = /net\suser\sHackMe\s\/add/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string17 = /net\suser\sHackMe\sozlq6qwm/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string18 = /PhrozenIO\/win\-brute\-logon/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string19 = /WinBruteLogon.{0,100}\s\-v\s\-u/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string20 = /WinBruteLogon\.dpr/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string21 = /WinBruteLogon\.dproj/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string22 = /WinBruteLogon\.exe/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string23 = /WinBruteLogon\.exe/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string24 = /WinBruteLogon\.res/ nocase ascii wide
        // Description: Crack any Microsoft Windows users password without any privilege (Guest account included)
        // Reference: https://github.com/PhrozenIO/win-brute-logon
        $string25 = /win\-brute\-logon\-master\.zip/ nocase ascii wide
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
