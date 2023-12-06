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
        $string1 = /\sinstall\skrbjack/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string2 = /\sKRB\shijacking\smodule\s/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string3 = /\s\-\-target\-name\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-\-executable\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string4 = /\/krbjack\.git/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string5 = /almandin\/krbjack/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string6 = /krbjack\s\-/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string7 = /krbjack\.tcpforward/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string8 = /krbjacker\.py/ nocase ascii wide
        // Description: A Kerberos AP-REQ hijacking tool with DNS unsecure updates abuse.
        // Reference: https://github.com/almandin/krbjack
        $string9 = /krbjack\-main/ nocase ascii wide

    condition:
        any of them
}
