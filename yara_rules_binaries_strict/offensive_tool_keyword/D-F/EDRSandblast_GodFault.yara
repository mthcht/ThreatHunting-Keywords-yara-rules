rule EDRSandblast_GodFault
{
    meta:
        description = "Detection patterns for the tool 'EDRSandblast-GodFault' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSandblast-GodFault"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string1 = /\sConfiguring\sWindows\sFirewall\srules\sto\sblock\sEDR\snetwork\saccess/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string2 = /\s\-\-unhook\-method\s.{0,100}\s\-\-dont\-unload\-driver\s.{0,100}\s\-\-dump\-output\s/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string3 = /\/EDRSandblast\// nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string4 = /\/LSASSProtectionBypass\/CredGuard\.c/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string5 = /\/UserlandBypass\/.{0,100}\.c/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string6 = /\\LSASSProtectionBypass\\/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string7 = /\\NtoskrnlOffsets\.csv/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string8 = /\\WdigestOffsets\.csv/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string9 = /04DFB6E4\-809E\-4C35\-88A1\-2CC5F1EBFEBD/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string10 = /3A2FCB56\-01A3\-41B3\-BDAA\-B25F45784B23/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string11 = /7E3E2ECE\-D1EB\-43C6\-8C83\-B52B7571954B/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string12 = /All\sEDR\sdrivers\swere\ssuccessfully\sremoved\sfrom\sKernel\scallbacks\!/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string13 = /and\sCredential\sGuard\swill\snot\sbe\sbypassed/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string14 = /C\:\\temp\\tmp\.tmp/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string15 = /Credential\sGuard\sbypass\smight\sfail\sif\sRunAsPPL\sis\senabled/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string16 = /EDRSandblast\.exe/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string17 = /EDRSandBlast\.h/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string18 = /EDRSandblast\.sln/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string19 = /EDRSandblast\.vcxproj/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string20 = /EDRSandblast_API\.c/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string21 = /EDRSandblast_API\.exe/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string22 = /EDRSandblast_API\.h/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string23 = /EDRSandblast_LsassDump\.c/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string24 = /EDRSandblast_LsassDump\.exe/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string25 = /EDRSandblast\-GodFault/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string26 = /FFA0FDDE\-BE70\-49E4\-97DE\-753304EF1113/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string27 = /LSASS\sdump\smight\sfail\sif\sRunAsPPL\sis\senabled/ nocase ascii wide
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
