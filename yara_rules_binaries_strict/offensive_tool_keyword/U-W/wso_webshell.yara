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
        $string2 = /1e7a48d3a266ff3a1521da0804858af56093f9c736c06be2bc6b46502a776d5d/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string3 = /DQojaW5jbHVkZSA8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCmludCBtYWluKGludCBhcmdjLCBjaGFyICphcmd/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string4 = /fa769dac7a0a94ee47d8ebe021eaba9e/ nocase ascii wide
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
        $string12 = /find\s\/\s\-perm\s\-2\s\-ls/ nocase ascii wide
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
        $string18 = /find\s\/\s\-type\sf\s\-perm\s\-02000\s\-ls/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string19 = /find\s\/\s\-type\sf\s\-perm\s\-04000\s\-ls/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string20 = /function\sactionBruteforce\(\)\s\{/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string21 = /I2luY2x1ZGUgPHN0ZGlvLmg\+DQojaW5jbHVkZSA8c3RyaW5nLmg\+DQojaW5jbHVkZSA8dW5pc3RkLmg\+DQojaW5jbHVkZSA8bmV0ZGIuaD4NCiNpbmNsdWRlIDxzdGRsaWI/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string22 = /IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lO/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string23 = /IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string24 = /mIcHyAmRaNe\/wso\-webshell/ nocase ascii wide
        // Description: wso php webshell
        // Reference: https://github.com/mIcHyAmRaNe/wso-webshell
        $string25 = /Welcome\sto\swso\swebshell\s/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
