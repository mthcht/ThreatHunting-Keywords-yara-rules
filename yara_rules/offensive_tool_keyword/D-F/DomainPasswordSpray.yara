rule DomainPasswordSpray
{
    meta:
        description = "Detection patterns for the tool 'DomainPasswordSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DomainPasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string1 = /DomainPasswordSpray/ nocase ascii wide
        // Description: DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!
        // Reference: https://github.com/dafthack/DomainPasswordSpray
        $string2 = /PasswordSpray\s/ nocase ascii wide

    condition:
        any of them
}
