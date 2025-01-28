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
        $string1 = " Configuring Windows Firewall rules to block EDR network access" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string2 = /\s\-\-unhook\-method\s.{0,1000}\s\-\-dont\-unload\-driver\s.{0,1000}\s\-\-dump\-output\s/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string3 = "/EDRSandblast/" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string4 = /\/LSASSProtectionBypass\/CredGuard\.c/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string5 = /\/UserlandBypass\/.{0,1000}\.c/ nocase ascii wide
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
        $string9 = "04DFB6E4-809E-4C35-88A1-2CC5F1EBFEBD" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string10 = "3A2FCB56-01A3-41B3-BDAA-B25F45784B23" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string11 = "7E3E2ECE-D1EB-43C6-8C83-B52B7571954B" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string12 = "All EDR drivers were successfully removed from Kernel callbacks!" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string13 = "and Credential Guard will not be bypassed" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string14 = /C\:\\temp\\tmp\.tmp/ nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string15 = "Credential Guard bypass might fail if RunAsPPL is enabled" nocase ascii wide
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
        $string25 = "EDRSandblast-GodFault" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string26 = "FFA0FDDE-BE70-49E4-97DE-753304EF1113" nocase ascii wide
        // Description: Integrates GodFault into EDR Sandblast achieving the same result without the use of any vulnerable drivers.
        // Reference: https://github.com/gabriellandau/EDRSandblast-GodFault
        $string27 = "LSASS dump might fail if RunAsPPL is enabled" nocase ascii wide

    condition:
        any of them
}
