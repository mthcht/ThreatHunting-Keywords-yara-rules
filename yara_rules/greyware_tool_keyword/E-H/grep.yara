rule grep
{
    meta:
        description = "Detection patterns for the tool 'grep' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "grep"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string1 = /.{0,1000}grep\s\-.{0,1000}\s.{0,1000}DBPassword.{0,1000}/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /.{0,1000}grep\s.{0,1000}password\s\/var\/www.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string3 = /.{0,1000}grep\s.{0,1000}password\..{0,1000}\s\/etc\/.{0,1000}\.conf.{0,1000}/ nocase ascii wide
        // Description: Look for users with a UID of 0
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4 = /.{0,1000}grep\s:0:\s\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string5 = /.{0,1000}grep\s\-i\spass\s.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: https://gtfobins.github.io/
        $string6 = /.{0,1000}grep\s\-i\suser\s.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string7 = /.{0,1000}grep\s\-R\sdb_passwd.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string8 = /.{0,1000}grep\s\-roiE\s.{0,1000}password.{0,1000}/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9 = /.{0,1000}grep.{0,1000}\|pwd\=\|passwd\=\|password\=.{0,1000}/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10 = /.{0,1000}grep.{0,1000}password\|pwd\|pass.{0,1000}/ nocase ascii wide
        // Description: search for passwords in memory and core dumps
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string11 = /.{0,1000}strings\s\-n\s.{0,1000}\s\/dev\/mem\s\|\sgrep\s\-i\spass.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
