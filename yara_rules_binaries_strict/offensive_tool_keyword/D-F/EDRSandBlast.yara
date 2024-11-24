rule EDRSandBlast
{
    meta:
        description = "Detection patterns for the tool 'EDRSandBlast' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSandBlast"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string1 = /\s\-\-nt\-offsets\s.{0,100}\.csv/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string2 = /\/EDRSandblast\.git/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string3 = /\\ntdlol\.txt/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string4 = "04DFB6E4-809E-4C35-88A1-2CC5F1EBFEBD" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string5 = "3A2FCB56-01A3-41B3-BDAA-B25F45784B23" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string6 = "7E3E2ECE-D1EB-43C6-8C83-B52B7571954B" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string7 = /EDRSandblast\.c/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string8 = /EDRSandblast\.exe/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string9 = /EDRSandblast\.sln/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string10 = "EDRSandblast_CLI" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string11 = "EDRSandblast_LsassDump" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string12 = "EDRSandblast_StaticLibrary" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string13 = "EDRSandblast-master" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string14 = "FFA0FDDE-BE70-49E4-97DE-753304EF1113" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string15 = /lsass\.exe.{0,100}C\:\\temp\\tmp\.tmp/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string16 = /LSASSProtectionBypass.{0,100}\// nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string17 = /NtoskrnlOffsets\.csv/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string18 = "wavestone-cdt/EDRSandblast" nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string19 = /\-\-wdigest\-offsets\s.{0,100}\.csv\s/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string20 = /WdigestOffsets\.csv/ nocase ascii wide
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
