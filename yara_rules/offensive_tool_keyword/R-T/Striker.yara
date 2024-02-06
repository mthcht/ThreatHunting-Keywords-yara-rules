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
        $string1 = /\.\/redirector\.py\s/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string2 = /\.striker\.local/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string3 = /\/agent\/C\/src\// nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string4 = /\/redirector\/redirector\.py/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string5 = /\/sites\-available\/striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string6 = /\/sites\-enabled\/striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string7 = /\/striker\.c/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string8 = /\/Striker\.git/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string9 = /\/striker\.local/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string10 = /4g3nt47\/Striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string11 = /bin\/striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string12 = /c2\.striker\./ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string13 = /localhost\:3000.{0,1000}striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string14 = /nginx\/striker\.log/ nocase ascii wide
        // Description: Recon & Vulnerability Scanning Suite for web services
        // Reference: https://github.com/s0md3v/Striker
        $string15 = /s0md3v.{0,1000}Striker/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string16 = /src\/obfuscator\.c/ nocase ascii wide
        // Description: Striker is a simple Command and Control (C2) program.
        // Reference: https://github.com/4g3nt47/Striker
        $string17 = /VITE_STRIKER_API/ nocase ascii wide

    condition:
        any of them
}
