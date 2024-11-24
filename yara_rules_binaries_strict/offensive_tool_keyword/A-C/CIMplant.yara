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
        $string1 = " -c active_users -u " nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string2 = " -c command_exec --execute tasklist" nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string3 = " -c command_exec --execute whoami" nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string4 = " -c edr_query " nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string5 = /\s\-c\slogon_events\s.{0,100}\s\-u\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string6 = /\s\-c\sls\s\-\-directory\s.{0,100}\s\-u\s.{0,100}\s\-p\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string7 = " -c process_kill --process " nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string8 = " -c service_mod --execute create -s " nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string9 = /\s\-c\supload\s\-\-fileto\s.{0,100}\s\-\-file\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string10 = /\s\-c\svacant_system\s.{0,100}\s\-u\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string11 = /\sCIMplant\.exe/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string12 = /\s\-s\s.{0,100}\s\-c\scommand_exec\s\-\-execute\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string13 = /\s\-s\s.{0,100}\s\-c\sdisable_wdigest\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string14 = /\s\-s\s.{0,100}\s\-c\sdisable_winrm\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string15 = /\s\-s\s.{0,100}\s\-c\senable_wdigest\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string16 = /\s\-s\s.{0,100}\s\-c\senable_winrm\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string17 = /\s\-s\s.{0,100}\s\-c\sremote_posh\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string18 = " --service fortynorth" nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string19 = /\.exe\s\-s\s.{0,100}\s\-c\sservice_mod\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string20 = /\/CIMplant\.exe/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string21 = /\/CIMplant\.git/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string22 = /\/CIMplant\/Commander\.cs/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string23 = /\\CIMplant\.exe/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string24 = /CIMplant\.exe\s/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string25 = /CIMplant\.sln/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string26 = "CIMplant-main" nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string27 = "FortyNorthSecurity/CIMplant" nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string28 = "RedSiege/CIMplant" nocase ascii wide
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
