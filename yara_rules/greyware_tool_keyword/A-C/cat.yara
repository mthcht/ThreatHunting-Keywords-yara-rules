rule cat
{
    meta:
        description = "Detection patterns for the tool 'cat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: show atftp history
        // Reference: N/A
        $string1 = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
        // Description: show bash history
        // Reference: N/A
        $string3 = /cat\s.{0,1000}\.bash_history/
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4 = /cat\s.{0,1000}\.bash_history/
        // Description: show mysql history
        // Reference: N/A
        $string5 = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string6 = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
        // Description: show nano history
        // Reference: N/A
        $string7 = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string8 = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
        // Description: show php history
        // Reference: N/A
        $string9 = /cat\s.{0,1000}\.php_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10 = /cat\s.{0,1000}\.php_history/ nocase ascii wide
        // Description: show zsh history
        // Reference: N/A
        $string11 = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: N/A
        $string12 = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string13 = /cat\s.{0,1000}bash\-history/
        // Description: deleting bash history
        // Reference: N/A
        $string14 = /cat\s\/dev\/null\s\>\s\$HISTFILE/ nocase ascii wide
        // Description: deleting log files
        // Reference: N/A
        $string15 = /cat\s\/dev\/null\s\>\s\/var\/log\/.{0,1000}\.log/
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string16 = /cat\s\/dev\/null\s\>\s\/var\/log\/auth\.log/
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string17 = "cat /dev/null > /var/log/messages"
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string18 = /cat\s\/dev\/null\s\>\s\~\/\.bash_history/
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string19 = "cat /dev/zero > /var/lol/messages"
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string20 = "cat /etc/passwd"
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string21 = "cat /etc/shadow"
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string22 = "cat /etc/sudoers"
        // Description: cat suspicious commands
        // Reference: N/A
        $string23 = /cat\s\/root\/\.aws\/credentials/ nocase ascii wide
        // Description: cat suspicious commands
        // Reference: N/A
        $string24 = /cat\s\/root\/\.ssh\/id_rsa/ nocase ascii wide

    condition:
        any of them
}
