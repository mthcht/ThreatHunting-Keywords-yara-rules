rule dialupass
{
    meta:
        description = "Detection patterns for the tool 'dialupass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dialupass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string1 = /\\Dialupass\.cfg/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string2 = /1e3ec12fbe9825c1eb044994d27c6fb97e5b2cee352d114b0ae6f8862e2a2dd5/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string3 = /598555a7e053c7456ee8a06a892309386e69d473c73284de9bbc0ba73b17e70a/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string4 = /Dialup\/VPN\sPassword\sRecovery/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string5 = /Dialup\/VPN\sPasswords\sList/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string6 = /Dialupass\.exe/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string7 = /Dialupass\.zip/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
