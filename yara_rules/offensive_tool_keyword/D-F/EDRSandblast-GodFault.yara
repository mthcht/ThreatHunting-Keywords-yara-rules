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
        $string1 = /.{0,1000}\sConfiguring\sWindows\sFirewall\srules\sto\sblock\sEDR\snetwork\saccess.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string2 = /.{0,1000}\s\-\-unhook\-method\s.{0,1000}\s\-\-dont\-unload\-driver\s.{0,1000}\s\-\-dump\-output\s.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string3 = /.{0,1000}\/EDRSandblast\/.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string4 = /.{0,1000}\/LSASSProtectionBypass\/CredGuard\.c.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string5 = /.{0,1000}\/UserlandBypass\/.{0,1000}\.c.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string6 = /.{0,1000}\\LSASSProtectionBypass\\.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string7 = /.{0,1000}\\NtoskrnlOffsets\.csv.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string8 = /.{0,1000}\\WdigestOffsets\.csv.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string9 = /.{0,1000}04DFB6E4\-809E\-4C35\-88A1\-2CC5F1EBFEBD.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string10 = /.{0,1000}3A2FCB56\-01A3\-41B3\-BDAA\-B25F45784B23.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string11 = /.{0,1000}7E3E2ECE\-D1EB\-43C6\-8C83\-B52B7571954B.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string12 = /.{0,1000}All\sEDR\sdrivers\swere\ssuccessfully\sremoved\sfrom\sKernel\scallbacks\!.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string13 = /.{0,1000}and\sCredential\sGuard\swill\snot\sbe\sbypassed.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string14 = /.{0,1000}C:\\temp\\tmp\.tmp.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string15 = /.{0,1000}Credential\sGuard\sbypass\smight\sfail\sif\sRunAsPPL\sis\senabled.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string16 = /.{0,1000}EDRSandblast\.exe.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string17 = /.{0,1000}EDRSandBlast\.h.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string18 = /.{0,1000}EDRSandblast\.sln.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string19 = /.{0,1000}EDRSandblast\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string20 = /.{0,1000}EDRSandblast_API\.c.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string21 = /.{0,1000}EDRSandblast_API\.exe.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string22 = /.{0,1000}EDRSandblast_API\.h.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string23 = /.{0,1000}EDRSandblast_LsassDump\.c.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string24 = /.{0,1000}EDRSandblast_LsassDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string25 = /.{0,1000}EDRSandblast\-GodFault.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string26 = /.{0,1000}FFA0FDDE\-BE70\-49E4\-97DE\-753304EF1113.{0,1000}/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string27 = /.{0,1000}LSASS\sdump\smight\sfail\sif\sRunAsPPL\sis\senabled.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
