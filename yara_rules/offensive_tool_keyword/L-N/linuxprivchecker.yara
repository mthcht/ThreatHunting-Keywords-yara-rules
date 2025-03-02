rule linuxprivchecker
{
    meta:
        description = "Detection patterns for the tool 'linuxprivchecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linuxprivchecker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string1 = /\s\-name\s\.htpasswd/
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string2 = " -perm -2000 -o -perm -4000"
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string3 = /\/linuxprivchecker\.git/
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string4 = "24d861124682031773ac0f6df9e5011b18a8d925c8c22469330826e64ccc2bab"
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string5 = "cat /etc/shadow"
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string6 = "cat /etc/sudoers 2>/dev/null"
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string7 = /find\s\/\s\-exec\s\/usr\/bin\/awk\s\'BEGIN\s\{system\(\\\\"\/bin\/bash\\\\"/
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string8 = /find.{0,1000}\s\-perm\s\-4000\s/
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string9 = /http\:\/\/www\.exploit\-db\.com\/exploits\// nocase ascii wide
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string10 = /linuxprivchecker\.py/
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string11 = "sleventyeleven/linuxprivchecker"

    condition:
        any of them
}
