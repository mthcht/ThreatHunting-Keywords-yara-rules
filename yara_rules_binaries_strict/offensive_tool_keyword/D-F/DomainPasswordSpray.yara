rule DomainPasswordSpray
{
    meta:
        description = "Detection patterns for the tool 'DomainPasswordSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DomainPasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string1 = /\s\-UserList\s.{0,100}\s\-Domain\s.{0,100}\s\-PasswordList\s.{0,100}\s\-OutFile\s/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string2 = /\/DomainPasswordSpray\.git/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string3 = /\\DomainPasswordSpray\\/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string4 = /\\DomainPasswordSpray\-master/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string5 = /\\sprayed\-creds\.txt/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string6 = /\\valid\-creds\.txt/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string7 = /\]\sAny\spasswords\sthat\swere\ssuccessfully\ssprayed\shave\sbeen\soutput\sto\s/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string8 = /\]\sPassword\sspraying\shas\sbegun\swith\s/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string9 = /\]\sPassword\sspraying\sis\scomplete/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string10 = "1a3c4069-8c11-4336-bef8-9a43c0ba60e2" nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string11 = "433d59580b95a3e3b82364729aac65643385eb4500c46eae2aab1c0567df03e6" nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string12 = /Cancelling\sthe\spassword\sspray\./ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string13 = "dafthack/DomainPasswordSpray" nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string14 = "DomainPasswordSpray" nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string15 = /DomainPasswordSpray\.ps1/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string16 = /DomainPasswordSpray\.psm1/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string17 = /Get\-DomainUserList\s\-Domain\s.{0,100}\s\-RemoveDisabled\s/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string18 = "Invoke-DomainPasswordSpray" nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string19 = "Invoke-DomainPasswordSpray" nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string20 = "mdavis332/DomainPasswordSpray" nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string21 = "PasswordSpray " nocase ascii wide
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
