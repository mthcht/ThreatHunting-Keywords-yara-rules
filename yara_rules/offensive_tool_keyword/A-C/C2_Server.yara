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
        $string1 = /\srev_shell\.py/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string2 = /\/C2_Server\.git/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string3 = /\/rev_shell\.py/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string4 = /\[\+\]\sBack\sto\sC\&C\sConsole/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string5 = /\[\+\]\sKeylogger\sstarted/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string6 = /\[\+\]\sKeylogger\sstopped/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string7 = /\\\srev_shell\.py/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string8 = /\\Chrome_pass\.db/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string9 = /192\.168\.0\.110\:1234/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string10 = /C\&C\s\=\>\s/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string11 = /C2_Server\-main/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string12 = /chrome_creds\.txt/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string13 = /Invoke\-WebRequest\shttps\:\/\/tinyurl\.com\// nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string14 = /keylog_dump/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string15 = /keylog_off/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string16 = /keylog_on/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string17 = /lnx_keylogger\.py/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string18 = /reveng007\/C2_Server/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string19 = /spoof_wani/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string20 = /spoof_wlan_creds/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string21 = /win_chrome_password_extractor\.py/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string22 = /win_keylogger\.py/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string23 = /win_wlan_passwd_and_wanip_extractor\.py/ nocase ascii wide

    condition:
        any of them
}
