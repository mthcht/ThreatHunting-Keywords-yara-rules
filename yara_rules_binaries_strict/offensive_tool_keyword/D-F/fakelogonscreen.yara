rule fakelogonscreen
{
    meta:
        description = "Detection patterns for the tool 'fakelogonscreen' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fakelogonscreen"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string1 = /\/fakelogonscreen/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string2 = /fakelogonscreen\s/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string3 = /fakelogonscreen.{0,100}\.zip/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string4 = /FakeLogonScreen\.csproj/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string5 = /fakelogonscreen\.exe/ nocase ascii wide
        // Description: FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk
        // Reference: https://github.com/bitsadmin/fakelogonscreen
        $string6 = /FakeLogonScreen\.sln/ nocase ascii wide
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
