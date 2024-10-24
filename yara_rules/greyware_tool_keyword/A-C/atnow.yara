rule atnow
{
    meta:
        description = "Detection patterns for the tool 'atnow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "atnow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string1 = /\/atnow\.exe/ nocase ascii wide
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string2 = /\/atnow\.zip/ nocase ascii wide
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string3 = /\\AtNow\s\\\\/ nocase ascii wide
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string4 = /\\atnow\.exe/ nocase ascii wide
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string5 = /\\atnow\.zip/ nocase ascii wide
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string6 = /\>Near\-Future\sCommand\sScheduler\</ nocase ascii wide
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string7 = /aa142160446a919eaba99ce15992f6e11b1fdaa7a9f569979a29068120f774cf/ nocase ascii wide
        // Description: AtNow is a command-line utility that schedules programs and commands to run in the near future - abused by TA
        // Reference: https://www.nirsoft.net/utils/atnow.html
        $string8 = /ProductName.{0,1000}\>AtNow\</ nocase ascii wide

    condition:
        any of them
}
