rule Recon_AD
{
    meta:
        description = "Detection patterns for the tool 'Recon-AD' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Recon-AD"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string1 = /\/Recon\-AD\.git/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string2 = /\/Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string3 = /\/Recon\-AD\-Computers\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string4 = /\/Recon\-AD\-Domain\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string5 = /\/Recon\-AD\-Groups\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string6 = /\/Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string7 = /\/Recon\-AD\-Users\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string8 = /\[\!\]\sCould\snot\sexecute\squery\.\sCould\snot\sbind\sto\sLDAP\:\/\/rootDSE\./ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string9 = /\\Outflank\-Recon\-AD\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string10 = /\\Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string11 = /\\Recon\-AD\-AllLocalGroups\.sln/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string12 = /\\Recon\-AD\-AllLocalGroups\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string13 = /\\Recon\-AD\-Computers\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string14 = /\\Recon\-AD\-Computers\.sln/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string15 = /\\Recon\-AD\-Computers\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string16 = /\\Recon\-AD\-Domain\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string17 = /\\Recon\-AD\-Domain\.sln/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string18 = /\\Recon\-AD\-Domain\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string19 = /\\Recon\-AD\-Groups\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string20 = /\\Recon\-AD\-Groups\.sln/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string21 = /\\Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string22 = /\\Recon\-AD\-LocalGroups\.sln/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string23 = /\\Recon\-AD\-LocalGroups\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string24 = /\\Recon\-AD\-master/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string25 = /\\Recon\-AD\-SPNs\.sln/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string26 = /\\Recon\-AD\-SPNs\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string27 = /\\Recon\-AD\-Users\.dll/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string28 = /\\Recon\-AD\-Users\.sln/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string29 = /\\ReflectiveDll\.cpp/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string30 = /\\ReflectiveLoader\.cpp/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string31 = /\\Src\\Recon\-AD\-Groups\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string32 = /\\Src\\Recon\-AD\-Users\\/ nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string33 = "_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H" nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string34 = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string35 = "outflanknl/Recon-AD" nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string36 = "Recon-AD-Computers All" nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string37 = "Recon-AD-Groups All" nocase ascii wide
        // Description: AD recon tool based on ADSI and reflective DLL
        // Reference: https://github.com/outflanknl/Recon-AD
        $string38 = "Recon-AD-Users All" nocase ascii wide
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
