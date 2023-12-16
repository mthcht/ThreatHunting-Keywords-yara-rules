rule whoami
{
    meta:
        description = "Detection patterns for the tool 'whoami' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whoami"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string1 = /whoami/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string2 = /whoami\.exe.{0,1000}\s\/groups/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string3 = /whoami\s\/priv/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string4 = /whoami\s\/all/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string5 = /whoami\s\/groups/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string6 = /whoami\s\/domain/ nocase ascii wide

    condition:
        any of them
}
