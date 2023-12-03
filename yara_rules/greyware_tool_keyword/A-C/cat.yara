rule cat
{
    meta:
        description = "Detection patterns for the tool 'cat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /.{0,1000}cat\s.{0,1000}\.atftp_history.{0,1000}/ nocase ascii wide
        // Description: show atftp history
        // Reference: N/A
        $string2 = /.{0,1000}cat\s.{0,1000}\.atftp_history.{0,1000}/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /.{0,1000}cat\s.{0,1000}\.bash_history.{0,1000}/ nocase ascii wide
        // Description: show bash history
        // Reference: N/A
        $string4 = /.{0,1000}cat\s.{0,1000}\.bash_history.{0,1000}/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string5 = /.{0,1000}cat\s.{0,1000}\.mysql_history.{0,1000}/ nocase ascii wide
        // Description: show mysql history
        // Reference: N/A
        $string6 = /.{0,1000}cat\s.{0,1000}\.mysql_history.{0,1000}/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string7 = /.{0,1000}cat\s.{0,1000}\.nano_history.{0,1000}/ nocase ascii wide
        // Description: show nano history
        // Reference: N/A
        $string8 = /.{0,1000}cat\s.{0,1000}\.nano_history.{0,1000}/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9 = /.{0,1000}cat\s.{0,1000}\.php_history.{0,1000}/ nocase ascii wide
        // Description: show php history
        // Reference: N/A
        $string10 = /.{0,1000}cat\s.{0,1000}\.php_history.{0,1000}/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: N/A
        $string11 = /.{0,1000}cat\s.{0,1000}\.zsh_history.{0,1000}/ nocase ascii wide
        // Description: show zsh history
        // Reference: N/A
        $string12 = /.{0,1000}cat\s.{0,1000}\.zsh_history.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string13 = /.{0,1000}cat\s.{0,1000}bash\-history.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string14 = /.{0,1000}cat\s\/dev\/null\s\>\s\/var\/log\/auth\.log.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string15 = /.{0,1000}cat\s\/dev\/null\s\>\s~\/\.bash_history.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string16 = /.{0,1000}cat\s\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string17 = /.{0,1000}cat\s\/etc\/shadow.{0,1000}/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string18 = /.{0,1000}cat\s\/etc\/sudoers.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
