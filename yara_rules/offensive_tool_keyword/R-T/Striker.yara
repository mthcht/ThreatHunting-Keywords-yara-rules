rule Striker
{
    meta:
        description = "Detection patterns for the tool 'Striker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Striker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string1 = /.{0,1000}\.\/redirector\.py\s.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string2 = /.{0,1000}\.striker\.local.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string3 = /.{0,1000}\/agent\/C\/src\/.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string4 = /.{0,1000}\/redirector\/redirector\.py.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string5 = /.{0,1000}\/sites\-available\/striker.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string6 = /.{0,1000}\/sites\-enabled\/striker.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string7 = /.{0,1000}\/striker\.c/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string8 = /.{0,1000}\/Striker\.git.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string9 = /.{0,1000}\/striker\.local.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string10 = /.{0,1000}4g3nt47\/Striker.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string11 = /.{0,1000}bin\/striker.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string12 = /.{0,1000}c2\.striker\..{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string13 = /.{0,1000}localhost:3000.{0,1000}striker.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string14 = /.{0,1000}nginx\/striker\.log.{0,1000}/ nocase ascii wide
        // Description: Recon & Vulnerability Scanning Suite for web services
        // Reference: https://github.com/s0md3v/Striker
        $string15 = /.{0,1000}s0md3v.{0,1000}Striker.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string16 = /.{0,1000}src\/obfuscator\.c.{0,1000}/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string17 = /.{0,1000}VITE_STRIKER_API.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
