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
        $string1 = /\s\-UserList\s.{0,1000}\s\-Domain\s.{0,1000}\s\-PasswordList\s.{0,1000}\s\-OutFile\s/ nocase ascii wide
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
        $string10 = /1a3c4069\-8c11\-4336\-bef8\-9a43c0ba60e2/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string11 = /433d59580b95a3e3b82364729aac65643385eb4500c46eae2aab1c0567df03e6/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string12 = /433d59580b95a3e3b82364729aac65643385eb4500c46eae2aab1c0567df03e6/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string13 = /Cancelling\sthe\spassword\sspray\./ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string14 = /dafthack\/DomainPasswordSpray/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string15 = /DomainPasswordSpray/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string16 = /DomainPasswordSpray\.ps1/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string17 = /DomainPasswordSpray\.psm1/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string18 = /Get\-DomainUserList\s\-Domain\s.{0,1000}\s\-RemoveDisabled\s/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string19 = /Invoke\-DomainPasswordSpray/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string20 = /mdavis332\/DomainPasswordSpray/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string21 = /PasswordSpray\s/ nocase ascii wide

    condition:
        any of them
}
