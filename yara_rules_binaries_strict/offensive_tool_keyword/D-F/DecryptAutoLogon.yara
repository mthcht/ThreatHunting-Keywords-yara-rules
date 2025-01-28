rule DecryptAutoLogon
{
    meta:
        description = "Detection patterns for the tool 'DecryptAutoLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptAutoLogon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string1 = /\/DecryptAutoLogon\.exe/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string2 = /\/DecryptAutoLogon\.git/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string3 = /\\DecryptAutoLogon\.exe/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string4 = /\\DecryptAutoLogon\.sln/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string5 = /\\DecryptAutoLogon\.sln/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string6 = /\\DecryptAutoLogon\-main/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string7 = ">DecryptAutoLogon<" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string8 = "015A37FC-53D0-499B-BFFE-AB88C5086040" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string9 = "6f14aa417bc4b85c47ef65bfed84e2b7728b1cb8bdd1c0cfc6eb6cd7fd0db7c0" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string10 = "83b65d33d21b01395de5b5537e36f18eb8f16237a64f3a8f17991dc652d1a61a" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string11 = "83b65d33d21b01395de5b5537e36f18eb8f16237a64f3a8f17991dc652d1a61a" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string12 = "9b723acfd67b3a99b88251493db23b8af6fedc8e36395096acec7332f61b86ba" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string13 = "c749894ea43c267418df93c7dd6b74ef25826d6c4a5461226ec800ae2efd1921" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string14 = "securesean/DecryptAutoLogon" nocase ascii wide
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
