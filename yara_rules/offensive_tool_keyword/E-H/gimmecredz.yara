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
        $string1 = /.{0,1000}dump_chrome_user.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string2 = /.{0,1000}dump_firefox_user.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string3 = /.{0,1000}dump_jenkins.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string4 = /.{0,1000}dump_keepassx.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string5 = /.{0,1000}dump_ssh_keys.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string6 = /.{0,1000}dump_tomcat.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string7 = /.{0,1000}dump_webconf.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string8 = /.{0,1000}dump_webpass.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string9 = /.{0,1000}dump_wifi_wpa_.{0,1000}/ nocase ascii wide
        // Description: This tool can help pentesters to quickly dump all credz from known location. such as .bash_history. config files. wordpress credentials. and so on
        // Reference: https://github.com/0xmitsurugi/gimmecredz
        $string10 = /.{0,1000}gimmecredz.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
