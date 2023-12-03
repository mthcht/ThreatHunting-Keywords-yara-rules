rule CIMplant
{
    meta:
        description = "Detection patterns for the tool 'CIMplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CIMplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string1 = /.{0,1000}\s\-c\sactive_users\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string2 = /.{0,1000}\s\-c\scommand_exec\s\-\-execute\stasklist.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string3 = /.{0,1000}\s\-c\scommand_exec\s\-\-execute\swhoami.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string4 = /.{0,1000}\s\-c\sedr_query\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string5 = /.{0,1000}\s\-c\slogon_events\s.{0,1000}\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string6 = /.{0,1000}\s\-c\sls\s\-\-directory\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string7 = /.{0,1000}\s\-c\sprocess_kill\s\-\-process\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string8 = /.{0,1000}\s\-c\sservice_mod\s\-\-execute\screate\s\-s\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string9 = /.{0,1000}\s\-c\supload\s\-\-fileto\s.{0,1000}\s\-\-file\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string10 = /.{0,1000}\s\-c\svacant_system\s.{0,1000}\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string11 = /.{0,1000}\sCIMplant\.exe.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string12 = /.{0,1000}\s\-s\s.{0,1000}\s\-c\scommand_exec\s\-\-execute\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string13 = /.{0,1000}\s\-s\s.{0,1000}\s\-c\sdisable_wdigest\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string14 = /.{0,1000}\s\-s\s.{0,1000}\s\-c\sdisable_winrm\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string15 = /.{0,1000}\s\-s\s.{0,1000}\s\-c\senable_wdigest\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string16 = /.{0,1000}\s\-s\s.{0,1000}\s\-c\senable_winrm\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string17 = /.{0,1000}\s\-s\s.{0,1000}\s\-c\sremote_posh\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string18 = /.{0,1000}\s\-\-service\sfortynorth.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string19 = /.{0,1000}\.exe\s\-s\s.{0,1000}\s\-c\sservice_mod\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string20 = /.{0,1000}\/CIMplant\.exe.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string21 = /.{0,1000}\/CIMplant\.git.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string22 = /.{0,1000}\/CIMplant\/Commander\.cs.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string23 = /.{0,1000}\\CIMplant\.exe.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string24 = /.{0,1000}CIMplant\.exe\s.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string25 = /.{0,1000}CIMplant\.sln.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string26 = /.{0,1000}CIMplant\-main.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string27 = /.{0,1000}FortyNorthSecurity\/CIMplant.{0,1000}/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string28 = /.{0,1000}RedSiege\/CIMplant.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
