rule Spray365
{
    meta:
        description = "Detection patterns for the tool 'Spray365' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spray365"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string1 = /.{0,1000}\s\-\-custom_user_agent.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string2 = /.{0,1000}\sgenerate\saudit\s\-ep\s.{0,1000}\-\-passwords_in_userfile.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string3 = /.{0,1000}\sgenerate\snormal\s\-ep\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-pf\s.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string4 = /.{0,1000}\sgenerate\snormal\s\-ep\sex\-plan\.s365\s.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string5 = /.{0,1000}\s\-\-random_user_agent.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string6 = /.{0,1000}\s\-\-show_invalid_creds.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string7 = /.{0,1000}\sspray\s\-ep\sex\-plan\.s365.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string8 = /.{0,1000}\.py\sspray\s\-ep\s.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string9 = /.{0,1000}\/spray\/spray\.py.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string10 = /.{0,1000}\/Spray365.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string11 = /.{0,1000}Spray365\.git.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string12 = /.{0,1000}spray365\.py.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string13 = /.{0,1000}spray365_results_.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string14 = /.{0,1000}\-\-user_file.{0,1000}\-\-password_file.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
