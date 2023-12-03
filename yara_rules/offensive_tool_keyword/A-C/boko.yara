rule boko
{
    meta:
        description = "Detection patterns for the tool 'boko' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "boko"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables as well as scripts an application may use that have the potential to be backdoored
        // Reference: https://github.com/bashexplode/boko
        $string1 = /.{0,1000}\/bashexplode\/boko.{0,1000}/ nocase ascii wide
        // Description: boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables as well as scripts an application may use that have the potential to be backdoored
        // Reference: https://github.com/bashexplode/boko
        $string2 = /.{0,1000}\/boko\.py.{0,1000}/ nocase ascii wide
        // Description: boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables as well as scripts an application may use that have the potential to be backdoored
        // Reference: https://github.com/bashexplode/boko
        $string3 = /.{0,1000}BackdoorableScript.{0,1000}/ nocase ascii wide
        // Description: boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables as well as scripts an application may use that have the potential to be backdoored
        // Reference: https://github.com/bashexplode/boko
        $string4 = /.{0,1000}boko\.py\s.{0,1000}/ nocase ascii wide
        // Description: boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables as well as scripts an application may use that have the potential to be backdoored
        // Reference: https://github.com/bashexplode/boko
        $string5 = /.{0,1000}bokoscanner\..{0,1000}/ nocase ascii wide
        // Description: boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables as well as scripts an application may use that have the potential to be backdoored
        // Reference: https://github.com/bashexplode/boko
        $string6 = /import\sboko.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
