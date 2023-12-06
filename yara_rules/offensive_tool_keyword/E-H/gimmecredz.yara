rule gimmecredz
{
    meta:
        description = "Detection patterns for the tool 'gimmecredz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gimmecredz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string1 = /dump_chrome_user/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string2 = /dump_firefox_user/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string3 = /dump_jenkins/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string4 = /dump_keepassx/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string5 = /dump_ssh_keys/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string6 = /dump_tomcat/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string7 = /dump_webconf/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string8 = /dump_webpass/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string9 = /dump_wifi_wpa_/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string10 = /gimmecredz/ nocase ascii wide

    condition:
        any of them
}
