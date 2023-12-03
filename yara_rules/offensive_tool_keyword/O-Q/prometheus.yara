rule prometheus
{
    meta:
        description = "Detection patterns for the tool 'prometheus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "prometheus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: malware C2
        // Reference: https://github.com/paranoidninja/0xdarkvortex-MalwareDevelopment
        $string1 = /.{0,1000}\/0xdarkvortex\-.{0,1000}/ nocase ascii wide
        // Description: malware C2
        // Reference: https://github.com/paranoidninja/0xdarkvortex-MalwareDevelopment
        $string2 = /.{0,1000}\/paranoidninja\/.{0,1000}/ nocase ascii wide
        // Description: malware C2
        // Reference: https://github.com/paranoidninja/0xdarkvortex-MalwareDevelopment
        $string3 = /.{0,1000}\/prometheus\.exe/ nocase ascii wide
        // Description: malware C2
        // Reference: https://github.com/paranoidninja/0xdarkvortex-MalwareDevelopment
        $string4 = /.{0,1000}0xdarkvortex\-MalwareDevelopment.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
