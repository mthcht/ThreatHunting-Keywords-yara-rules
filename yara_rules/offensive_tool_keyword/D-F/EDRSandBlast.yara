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
        $string1 = /\s\-\-nt\-offsets\s.{0,1000}\.csv/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string2 = /\/EDRSandblast\.git/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string3 = /\\ntdlol\.txt/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string4 = /04DFB6E4\-809E\-4C35\-88A1\-2CC5F1EBFEBD/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string5 = /3A2FCB56\-01A3\-41B3\-BDAA\-B25F45784B23/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string6 = /7E3E2ECE\-D1EB\-43C6\-8C83\-B52B7571954B/ nocase ascii wide
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
        $string10 = /EDRSandblast_CLI/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string11 = /EDRSandblast_LsassDump/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string12 = /EDRSandblast_StaticLibrary/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string13 = /EDRSandblast\-master/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string14 = /FFA0FDDE\-BE70\-49E4\-97DE\-753304EF1113/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string15 = /lsass\.exe.{0,1000}C\:\\temp\\tmp\.tmp/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string16 = /LSASSProtectionBypass.{0,1000}\// nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string17 = /NtoskrnlOffsets\.csv/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string18 = /wavestone\-cdt\/EDRSandblast/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string19 = /\-\-wdigest\-offsets\s.{0,1000}\.csv\s/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string20 = /WdigestOffsets\.csv/ nocase ascii wide

    condition:
        any of them
}
