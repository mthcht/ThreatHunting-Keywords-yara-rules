rule SharpGPOAbuse
{
    meta:
        description = "Detection patterns for the tool 'SharpGPOAbuse' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGPOAbuse"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string1 = /.{0,1000}\s\-\-AddComputerTask\s\-\-TaskName\s.{0,1000}\s\-\-Author\s.{0,1000}\s\-\-Command\s.{0,1000}\s\-\-Arguments\s.{0,1000}\s\-\-GPOName\s.{0,1000}/ nocase ascii wide
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string2 = /.{0,1000}\s\-\-AddLocalAdmin\s\-\-UserAccount\s.{0,1000}\s\-\-GPOName\s.{0,1000}/ nocase ascii wide
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string3 = /.{0,1000}\s\-\-AddUserRights\s\-\-UserRights\s.{0,1000}\s\-\-UserAccount\s.{0,1000}\s\-\-GPOName\s.{0,1000}/ nocase ascii wide
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string4 = /.{0,1000}\s\-\-AddUserScript\s\-\-ScriptName\s.{0,1000}\s\-\-ScriptContents\s.{0,1000}\s\-\-GPOName\s.{0,1000}/ nocase ascii wide
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string5 = /.{0,1000}\s\-\-GPOName\s.{0,1000}\s\-\-FilterEnabled\s\-\-TargetDnsName\s.{0,1000}/ nocase ascii wide
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string6 = /.{0,1000}\sNewLocalAdmin\(.{0,1000}/ nocase ascii wide
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a users edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string7 = /.{0,1000}SharpGPOAbuse.{0,1000}/ nocase ascii wide
        // Description: SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
        // Reference: https://github.com/FSecureLABS/SharpGPOAbuse
        $string8 = /.{0,1000}SharpGPOAbuse.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
