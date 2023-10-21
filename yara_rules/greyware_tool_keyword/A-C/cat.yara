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
        $string1 = /cat\s.*\.atftp_history/ nocase ascii wide
        // Description: show atftp history
        // Reference: N/A
        $string2 = /cat\s.*\.atftp_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /cat\s.*\.bash_history/ nocase ascii wide
        // Description: show bash history
        // Reference: N/A
        $string4 = /cat\s.*\.bash_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string5 = /cat\s.*\.mysql_history/ nocase ascii wide
        // Description: show mysql history
        // Reference: N/A
        $string6 = /cat\s.*\.mysql_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string7 = /cat\s.*\.nano_history/ nocase ascii wide
        // Description: show nano history
        // Reference: N/A
        $string8 = /cat\s.*\.nano_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9 = /cat\s.*\.php_history/ nocase ascii wide
        // Description: show php history
        // Reference: N/A
        $string10 = /cat\s.*\.php_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: N/A
        $string11 = /cat\s.*\.zsh_history/ nocase ascii wide
        // Description: show zsh history
        // Reference: N/A
        $string12 = /cat\s.*\.zsh_history/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string13 = /cat\s.*bash\-history/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string14 = /cat\s\/dev\/null\s\>\s\/var\/log\/auth\.log/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string15 = /cat\s\/dev\/null\s\>\s~\/\.bash_history/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string16 = /cat\s\/etc\/passwd/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string17 = /cat\s\/etc\/shadow/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string18 = /cat\s\/etc\/sudoers/ nocase ascii wide

    condition:
        any of them
}