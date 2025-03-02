rule mRemoteNG_Decrypt
{
    meta:
        description = "Detection patterns for the tool 'mRemoteNG-Decrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mRemoteNG-Decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string1 = /\/decipher_mremoteng\.iml/ nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/haseebT/mRemoteNG-Decrypt
        $string2 = "/mRemoteNG-Decrypt" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string3 = /\/mremoteng\-decrypt\.git/ nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string4 = "/mremoteng-decrypt/releases/download/" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string5 = "/mremoteng-decrypt/tarball/" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string6 = "/mremoteng-decrypt/zipball/" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string7 = /\\mremoteng\-decrypt\\/ nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string8 = "3e43822dce57d12ca13a1888e2b5d653dfbf9815dd5cda87e1fc1ce29a423170" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string9 = "405cd1547ee19c39e0afa83ba8ac7a53a4f88c95447df355540d82a5aa74e484" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string10 = "736c69887df76672923ad7ae8b1b1754f13f96d3ae5e2eea7259e29163af71d0" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string11 = "938e42fe50266db91748e07d22a54e73c9d5d25d81b5d50e475f3fc6e09d1cb1" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string12 = "bbf4a68d05e79d8d2ce0bbd948a713ddafcb74b4ababa5f43c154592bc09e897" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string13 = "bc600d653659564adc9f526dbba502d0b2fa47c82192b0c14fd25f45d81eec6d" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string14 = "bee821a0267335398f5db2ced5c2e2687ced844c8a1627d111d4fd0692b791e6" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string15 = /decipher_mremoteng\.jar/ nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string16 = "ebffe9aadf0e6b25df7573ca04de5b12d79ad0103d1fd936e333660b4359006c" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string17 = "edf8c7fe2bd7241aafa9109be239698bc7e840097ffaec13a6a593876bdb6e97" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string18 = "kmahyyg/mremoteng-decrypt" nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/haseebT/mRemoteNG-Decrypt
        $string19 = /mremoteng_decrypt\.py/ nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/kmahyyg/mremoteng-decrypt
        $string20 = /mremoteng_decrypt\.py/ nocase ascii wide
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
