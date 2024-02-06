rule SharpSQLPwn
{
    meta:
        description = "Detection patterns for the tool 'SharpSQLPwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSQLPwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# tool to identify and exploit weaknesses within MSSQL instances in Active Directory environments
        // Reference: https://github.com/lefayjey/SharpSQLPwn
        $string1 = /\s\/cmdtech\:.{0,1000}\s\/cmd\:.{0,1000}\s\/impuser\:/ nocase ascii wide
        // Description: C# tool to identify and exploit weaknesses within MSSQL instances in Active Directory environments
        // Reference: https://github.com/lefayjey/SharpSQLPwn
        $string2 = /\s\/cmdtech\:.{0,1000}\s\/cmd\:.{0,1000}\s\/query\:/ nocase ascii wide
        // Description: C# tool to identify and exploit weaknesses within MSSQL instances in Active Directory environments
        // Reference: https://github.com/lefayjey/SharpSQLPwn
        $string3 = /\s\/modules\:.{0,1000}\s\/target\:.{0,1000}\s\/linkedsql\:/ nocase ascii wide
        // Description: C# tool to identify and exploit weaknesses within MSSQL instances in Active Directory environments
        // Reference: https://github.com/lefayjey/SharpSQLPwn
        $string4 = /SharpSQLPwn/ nocase ascii wide

    condition:
        any of them
}
