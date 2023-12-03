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
        $string1 = /.{0,1000}bad\sclient\spublic\sDH\svalue.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string2 = /.{0,1000}Corrupted\sMAC\son\sinput.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string3 = /.{0,1000}error\sin\slibcrypto.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string4 = /.{0,1000}fatal:\sbuffer_get_string:\sbad\sstring.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string5 = /.{0,1000}incorrect\ssignature.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string6 = /.{0,1000}invalid\scertificate\ssigning\skey.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string7 = /.{0,1000}invalid\selliptic\scurve\svalue.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string8 = /.{0,1000}Local:\scrc32\scompensation\sattack.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string9 = /.{0,1000}unexpected\sbytes\sremain\safter\sdecoding.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string10 = /.{0,1000}unexpected\sinternal\serror.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string11 = /.{0,1000}unknown\sor\sunsupported\skey\stype.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
