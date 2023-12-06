rule ntdissector
{
    meta:
        description = "Detection patterns for the tool 'ntdissector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdissector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string1 = /\s\-ntds\sNTDS\.dit\s\s\-filters/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string2 = /\s\-ntds\sNTDS\.dit\s\-system\sSYSTEM\s\-outputdir\s\// nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string3 = /\.\/ntdissector/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string4 = /\/\.ntdissector/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string5 = /\/ntdissector\.git/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string6 = /\/ntdissector\// nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string7 = /dBCSPwd.{0,1000}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string8 = /ntdissector\s\-/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string9 = /ntdissector\-main/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string10 = /ntds\/ntds\.py/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string11 = /synacktiv\/ntdissector/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string12 = /user_to_secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}
