rule ItWasAllADream
{
    meta:
        description = "Detection patterns for the tool 'ItWasAllADream' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ItWasAllADream"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PrintNightmare (CVE-2021-34527) Python Scanner. Scan entire subnets for hosts vulnerable to the PrintNightmare RCE
        // Reference: https://github.com/byt3bl33d3r/ItWasAllADream
        $string1 = /.{0,1000}\/ItWasAllADream\.git.{0,1000}/ nocase ascii wide
        // Description: A PrintNightmare (CVE-2021-34527) Python Scanner. Scan entire subnets for hosts vulnerable to the PrintNightmare RCE
        // Reference: https://github.com/byt3bl33d3r/ItWasAllADream
        $string2 = /.{0,1000}byt3bl33d3r\/ItWasAllADream.{0,1000}/ nocase ascii wide
        // Description: A PrintNightmare (CVE-2021-34527) Python Scanner. Scan entire subnets for hosts vulnerable to the PrintNightmare RCE
        // Reference: https://github.com/byt3bl33d3r/ItWasAllADream
        $string3 = /.{0,1000}itwasalladream\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: A PrintNightmare (CVE-2021-34527) Python Scanner. Scan entire subnets for hosts vulnerable to the PrintNightmare RCE
        // Reference: https://github.com/byt3bl33d3r/ItWasAllADream
        $string4 = /.{0,1000}itwasalladream.{0,1000}bogus\.dll.{0,1000}/ nocase ascii wide
        // Description: A PrintNightmare (CVE-2021-34527) Python Scanner. Scan entire subnets for hosts vulnerable to the PrintNightmare RCE
        // Reference: https://github.com/byt3bl33d3r/ItWasAllADream
        $string5 = /.{0,1000}ItWasAllADream\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
