rule conpass
{
    meta:
        description = "Detection patterns for the tool 'conpass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "conpass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string1 = /b09a40f998e8bc112841842ed56d8e843e5df98f4b53657098924fd10325a4b9/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string2 = /conpass\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string3 = /conpass\sv.{0,1000}\s\-\sContinuous\spassword\sspraying\stool/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string4 = /DumpNTLMInfo\.py/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string5 = /ed99b1d4757d0848ced6b91f18326c42127f6f79ad1cc7e7fafeee91388004e3/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string6 = /from\sconpass\.ntlminfo\simport\s/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string7 = /from\sconpass\.password\simport\s/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string8 = /Hackndo\/conpass/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string9 = /impacket\.smbconnection/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string10 = /login\-securite\/conpass/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string11 = /pip\sinstall\sconpass/ nocase ascii wide
        // Description: Continuous password spraying tool
        // Reference: https://github.com/login-securite/conpass
        $string12 = /Romain\sBentz\s\(pixis\s\-\s\@hackanddo\)/ nocase ascii wide

    condition:
        any of them
}
