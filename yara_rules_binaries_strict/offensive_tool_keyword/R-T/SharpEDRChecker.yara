rule SharpEDRChecker
{
    meta:
        description = "Detection patterns for the tool 'SharpEDRChecker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEDRChecker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string1 = /\sSharpEDRChecker/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string2 = /\/SharpEDRChecker\-.{0,100}\.zip/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string3 = /\/SharpEDRChecker\.git/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string4 = /\/SharpEDRChecker\// nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string5 = /\[\!\]\[\!\]\[\!\]\sChecking\sDirectories\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string6 = /\[\!\]\[\!\]\[\!\]\sChecking\sdrivers\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string7 = /\[\!\]\[\!\]\[\!\]\sChecking\smodules\sloaded\sin\syour\scurrent\sprocess\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string8 = /\[\!\]\[\!\]\[\!\]\sChecking\sServices\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string9 = /\[\!\]\[\!\]\[\!\]\sEDR\sChecks\sComplete\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string10 = /\[\!\]\[\!\]\[\!\]\sWelcome\sto\sSharpEDRChecker\sby\s\@PwnDexter\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string11 = /\\SharpEDRChecker\-.{0,100}\.zip/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string12 = /\\SharpEDRChecker\.cs/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string13 = /\\SharpEDRChecker\.sln/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string14 = /\\SharpEDRChecker\\/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string15 = /14e8721290b9457ec4c641c48aaa111df18eeed8e1c208da18666d3f3dd8e2ff/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string16 = /BDFEE233\-3FED\-42E5\-AA64\-492EB2AC7047/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string17 = /e3038dfa23e4c4707e73f5b4a214fe35796b805ef213e0e84da1e20cd5643fa5/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string18 = /Invoke\-EDRChecker/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string19 = /PwnDexter\/SharpEDRChecker/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string20 = /SharpEDRChecker\.exe/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string21 = /SharpEDRChecker\.Program/ nocase ascii wide
        // Description: Checks for the presence of known defensive products such as AV/EDR and logging tools
        // Reference: https://github.com/PwnDexter/SharpEDRChecker
        $string22 = /SharpEDRChecker\/releases/ nocase ascii wide
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
