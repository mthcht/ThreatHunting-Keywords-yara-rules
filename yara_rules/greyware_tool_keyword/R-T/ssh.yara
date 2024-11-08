rule ssh
{
    meta:
        description = "Detection patterns for the tool 'ssh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string1 = /bad\sclient\spublic\sDH\svalue/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string2 = /fatal\:\sbuffer_get_string\:\sbad\sstring/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string3 = /Local\:\scrc32\scompensation\sattack/ nocase ascii wide
        // Description: modification of the sshd configuration file - couldbe an attacker establishing persistence or a legitimate admin behavior
        // Reference: https://x.com/mthcht/status/1827714529687658796
        $string4 = /nano\s\/etc\/ssh\/sshd_config/ nocase ascii wide
        // Description: Binding to port 445 on Windows with ssh - useful for NTLM relaying
        // Reference: https://x.com/0x64616e/status/1817149974724956286
        $string5 = /ssh\.exe\s\-L\s0\.0\.0\.0\:445\:127\.0\.0\.1\:445\s/ nocase ascii wide
        // Description: modification of the sshd configuration file - couldbe an attacker establishing persistence or a legitimate admin behavior
        // Reference: https://x.com/mthcht/status/1827714529687658796
        $string6 = /vim\s\/etc\/ssh\/sshd_config/ nocase ascii wide

    condition:
        any of them
}
