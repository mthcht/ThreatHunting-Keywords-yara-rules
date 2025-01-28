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
        $string1 = /grep\s\-.{0,1000}\s.{0,1000}DBPassword/
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /grep\s.{0,1000}password\s\/var\/www/
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string3 = /grep\s.{0,1000}password\..{0,1000}\s\/etc\/.{0,1000}\.conf/
        // Description: Look for users with a UID of 0
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4 = "grep :0: /etc/passwd"
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string5 = "grep -i pass "
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: https://gtfobins.github.io/
        $string6 = "grep -i user "
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string7 = "grep -R db_passwd"
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string8 = /grep\s\-roiE\s.{0,1000}password/
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9 = /grep.{0,1000}\|pwd\=\|passwd\=\|password\=/
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10 = /grep.{0,1000}password\|pwd\|pass/
        // Description: search for passwords in memory and core dumps
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string11 = /strings\s\-n\s.{0,1000}\s\/dev\/mem\s\|\sgrep\s\-i\spass/

    condition:
        any of them
}
