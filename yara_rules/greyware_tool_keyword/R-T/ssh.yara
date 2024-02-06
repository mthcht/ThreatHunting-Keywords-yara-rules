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
        $string2 = /Corrupted\sMAC\son\sinput/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string3 = /error\sin\slibcrypto/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string4 = /fatal\:\sbuffer_get_string\:\sbad\sstring/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string5 = /incorrect\ssignature/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string6 = /invalid\scertificate\ssigning\skey/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string7 = /invalid\selliptic\scurve\svalue/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string8 = /Local\:\scrc32\scompensation\sattack/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string9 = /unexpected\sbytes\sremain\safter\sdecoding/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string10 = /unexpected\sinternal\serror/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string11 = /unknown\sor\sunsupported\skey\stype/ nocase ascii wide

    condition:
        any of them
}
