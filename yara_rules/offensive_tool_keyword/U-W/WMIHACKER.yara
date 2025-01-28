rule WMIHACKER
{
    meta:
        description = "Detection patterns for the tool 'WMIHACKER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIHACKER"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string1 = /\sWMIHACKER\.vbs/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string2 = /\swmihacker_0\.4\.vbe/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string3 = /\sWMIHACKER_0\.6\.vbs/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string4 = /\/WMIHACKER\.git/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string5 = /\/WMIHACKER\.vbs/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string6 = /\\WMIHACKER\.vbs/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string7 = /\\wmihacker_0\.4\.vbe/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string8 = /\\WMIHACKER_0\.6\.vbs/ nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string9 = "131bacdddd51f0d5d869b63912606719cd8f7a8f5b5f4237cbdb5c2e22e2cba2" nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string10 = "iangshan@360RedTeam" nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string11 = "rootclay/WMIHACKER" nocase ascii wide
        // Description: Bypass anti-virus software lateral movement command execution test tool - No need 445 Port
        // Reference: https://github.com/rootclay/WMIHACKER
        $string12 = "WMIHACKER : Login -> OK" nocase ascii wide

    condition:
        any of them
}
