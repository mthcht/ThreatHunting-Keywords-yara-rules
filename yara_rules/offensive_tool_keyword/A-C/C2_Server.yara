rule C2_Server
{
    meta:
        description = "Detection patterns for the tool 'C2_Server' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2_Server"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string1 = /.{0,1000}\srev_shell\.py.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string2 = /.{0,1000}\/C2_Server\.git.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string3 = /.{0,1000}\/rev_shell\.py.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string4 = /.{0,1000}\[\+\]\sBack\sto\sC\&C\sConsole.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string5 = /.{0,1000}\[\+\]\sKeylogger\sstarted.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string6 = /.{0,1000}\[\+\]\sKeylogger\sstopped.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string7 = /.{0,1000}\\\srev_shell\.py.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string8 = /.{0,1000}\\Chrome_pass\.db.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string9 = /.{0,1000}192\.168\.0\.110:1234.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string10 = /.{0,1000}C\&C\s\=\>\s.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string11 = /.{0,1000}C2_Server\-main.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string12 = /.{0,1000}chrome_creds\.txt.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string13 = /.{0,1000}Invoke\-WebRequest\shttps:\/\/tinyurl\.com\/.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string14 = /.{0,1000}keylog_dump.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string15 = /.{0,1000}keylog_off.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string16 = /.{0,1000}keylog_on.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string17 = /.{0,1000}lnx_keylogger\.py.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string18 = /.{0,1000}reveng007\/C2_Server.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string19 = /.{0,1000}spoof_wani.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string20 = /.{0,1000}spoof_wlan_creds.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string21 = /.{0,1000}win_chrome_password_extractor\.py.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string22 = /.{0,1000}win_keylogger\.py.{0,1000}/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string23 = /.{0,1000}win_wlan_passwd_and_wanip_extractor\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
