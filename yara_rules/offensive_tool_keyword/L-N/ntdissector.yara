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
        $string1 = /.{0,1000}\s\-ntds\sNTDS\.dit\s\s\-filters.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string2 = /.{0,1000}\s\-ntds\sNTDS\.dit\s\-system\sSYSTEM\s\-outputdir\s\/.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string3 = /.{0,1000}\.\/ntdissector.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string4 = /.{0,1000}\/\.ntdissector.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string5 = /.{0,1000}\/ntdissector\.git.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string6 = /.{0,1000}\/ntdissector\/.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string7 = /.{0,1000}dBCSPwd.{0,1000}aad3b435b51404eeaad3b435b51404ee.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string8 = /.{0,1000}ntdissector\s\-.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string9 = /.{0,1000}ntdissector\-main.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string10 = /.{0,1000}ntds\/ntds\.py.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string11 = /.{0,1000}synacktiv\/ntdissector.{0,1000}/ nocase ascii wide
        // Description: Ntdissector is a tool for parsing records of an NTDS database. Records are dumped in JSON format and can be filtered by object class.
        // Reference: https://github.com/synacktiv/ntdissector
        $string12 = /.{0,1000}user_to_secretsdump\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
