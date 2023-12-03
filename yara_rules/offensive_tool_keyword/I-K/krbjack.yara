rule krbjack
{
    meta:
        description = "Detection patterns for the tool 'krbjack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krbjack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string1 = /.{0,1000}\sinstall\skrbjack.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string2 = /.{0,1000}\sKRB\shijacking\smodule\s.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string3 = /.{0,1000}\s\-\-target\-name\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-\-executable\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string4 = /.{0,1000}\/krbjack\.git.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string5 = /.{0,1000}almandin\/krbjack.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string6 = /.{0,1000}krbjack\s\-.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string7 = /.{0,1000}krbjack\.tcpforward.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string8 = /.{0,1000}krbjacker\.py.{0,1000}/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string9 = /.{0,1000}krbjack\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
