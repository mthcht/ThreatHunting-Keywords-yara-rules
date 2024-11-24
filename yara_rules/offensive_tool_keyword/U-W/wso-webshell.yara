rule wso_webshell
{
    meta:
        description = "Detection patterns for the tool 'wso-webshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wso-webshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string1 = /\/wso\-webshell\.git/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string2 = "1e7a48d3a266ff3a1521da0804858af56093f9c736c06be2bc6b46502a776d5d" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string3 = "DQojaW5jbHVkZSA8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCmludCBtYWluKGludCBhcmdjLCBjaGFyICphcmd" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string4 = "fa769dac7a0a94ee47d8ebe021eaba9e" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string5 = /find\s\.\s\-perm\s\-2\s\-ls/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string6 = /find\s\.\s\-type\sf\s\-name\s\.bash_history/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string7 = /find\s\.\s\-type\sf\s\-name\s\.fetchmailrc/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string8 = /find\s\.\s\-type\sf\s\-name\s\.htpasswd/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string9 = /find\s\.\s\-type\sf\s\-name\sservice\.pwd/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string10 = /find\s\.\s\-type\sf\s\-perm\s\-02000\s\-ls/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string11 = /find\s\.\s\-type\sf\s\-perm\s\-04000\s\-ls/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string12 = "find / -perm -2 -ls" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string13 = /find\s\/\s\-type\sf\s\-name\s\.bash_history/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string14 = /find\s\/\s\-type\sf\s\-name\s\.fetchmailrc/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string15 = /find\s\/\s\-type\sf\s\-name\s\.htpasswd/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string16 = /find\s\/\s\-type\sf\s\-name\sconfig\.inc\.php/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string17 = /find\s\/\s\-type\sf\s\-name\sservice\.pwd/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string18 = "find / -type f -perm -02000 -ls" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string19 = "find / -type f -perm -04000 -ls" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string20 = /function\sactionBruteforce\(\)\s\{/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string21 = /I2luY2x1ZGUgPHN0ZGlvLmg\+DQojaW5jbHVkZSA8c3RyaW5nLmg\+DQojaW5jbHVkZSA8dW5pc3RkLmg\+DQojaW5jbHVkZSA8bmV0ZGIuaD4NCiNpbmNsdWRlIDxzdGRsaWI/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string22 = "IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lO" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string23 = "IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string24 = "mIcHyAmRaNe/wso-webshell" nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string25 = "Welcome to wso webshell " nocase ascii wide

    condition:
        any of them
}
