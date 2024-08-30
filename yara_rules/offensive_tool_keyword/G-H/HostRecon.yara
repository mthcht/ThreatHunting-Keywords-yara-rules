rule HostRecon
{
    meta:
        description = "Detection patterns for the tool 'HostRecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HostRecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Invoke-HostRecon runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase of an engagement. It gathers information about the local system. users. and domain information. It does not use any 'net. 'ipconfig. 'whoami. 'netstat. or other system commands to help avoid detection.
        // Reference: https://github.com/dafthack/HostRecon
        $string1 = /dafthack\/HostRecon/ nocase ascii wide
        // Description: Invoke-HostRecon runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase of an engagement. It gathers information about the local system. users. and domain information. It does not use any 'net. 'ipconfig. 'whoami. 'netstat. or other system commands to help avoid detection.
        // Reference: https://github.com/dafthack/HostRecon
        $string2 = /Invoke\-HostRecon/ nocase ascii wide

    condition:
        any of them
}
