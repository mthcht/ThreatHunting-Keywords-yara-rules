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
        $string1 = /.{0,1000}\s\-\-nt\-offsets\s.{0,1000}\.csv.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string2 = /.{0,1000}\/EDRSandblast\.git.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string3 = /.{0,1000}\\ntdlol\.txt.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string4 = /.{0,1000}04DFB6E4\-809E\-4C35\-88A1\-2CC5F1EBFEBD.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string5 = /.{0,1000}3A2FCB56\-01A3\-41B3\-BDAA\-B25F45784B23.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string6 = /.{0,1000}7E3E2ECE\-D1EB\-43C6\-8C83\-B52B7571954B.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string7 = /.{0,1000}EDRSandblast\.c.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string8 = /.{0,1000}EDRSandblast\.exe.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string9 = /.{0,1000}EDRSandblast\.sln.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string10 = /.{0,1000}EDRSandblast_CLI.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string11 = /.{0,1000}EDRSandblast_LsassDump.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string12 = /.{0,1000}EDRSandblast_StaticLibrary.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string13 = /.{0,1000}EDRSandblast\-master.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string14 = /.{0,1000}FFA0FDDE\-BE70\-49E4\-97DE\-753304EF1113.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string15 = /.{0,1000}lsass\.exe.{0,1000}C:\\temp\\tmp\.tmp.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string16 = /.{0,1000}LSASSProtectionBypass.{0,1000}\// nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string17 = /.{0,1000}NtoskrnlOffsets\.csv.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string18 = /.{0,1000}wavestone\-cdt\/EDRSandblast.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string19 = /.{0,1000}\-\-wdigest\-offsets\s.{0,1000}\.csv\s.{0,1000}/ nocase ascii wide
        // Description: EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections
        // Reference: https://github.com/wavestone-cdt/EDRSandblast
        $string20 = /.{0,1000}WdigestOffsets\.csv.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
