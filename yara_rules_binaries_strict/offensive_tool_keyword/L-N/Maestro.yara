rule Maestro
{
    meta:
        description = "Detection patterns for the tool 'Maestro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Maestro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string1 = /\\ROADtoken\\bin\\/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string2 = /4EE2C7E8\-095D\-490A\-9465\-9B4BB9070669/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string3 = /8fff8971be038906411561230e11adae6f576dca6761375cbcf61d3e7b2e4cd4/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string4 = /await\sDeleteIntuneCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string5 = /await\sDeleteIntuneScriptCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string6 = /await\sExecIntuneAppCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string7 = /await\sExecIntuneCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string8 = /await\sExecIntuneDeviceQueryCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string9 = /await\sExecIntuneScriptCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string10 = /await\sExecIntuneSyncCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string11 = /await\sGetAccessTokenCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string12 = /await\sGetEntraCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string13 = /await\sGetEntraGroupsCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string14 = /await\sGetEntraUsersCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string15 = /await\sGetIntuneAppsCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string16 = /await\sGetIntuneCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string17 = /await\sGetIntuneDevicesCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string18 = /await\sGetIntuneScriptsCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string19 = /await\sGetPrtCookieCommand\.Exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string20 = /c0ec4fdda78c68d5b982664a121efb8939808171d11d7a1e9bc17db565d99ee1/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string21 = /C9AF8FE1\-CDFC\-4DDD\-B314\-B44AD5EAD552/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string22 = /dsregcmd\.exe\s\/status/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string23 = /maestro\.exe\sexec/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string24 = /Mayyhem\/Maestro/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string25 = /RequestAADRefreshToken\.exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string26 = /roadtoken\.exe/ nocase ascii wide
        // Description: Maestro is a post-exploitation tool that simplifies interaction with Intune/EntraID from a C2 agent on a user's workstation bypassing the need for user password knowledge - token manipulation or Azure authentication processes
        // Reference: https://github.com/Mayyhem/Maestro
        $string27 = /RVLextu9ni633iqW54ktzkU4kTDgekRFY8ao9gSwM78\=/ nocase ascii wide
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
