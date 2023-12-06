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
        $string1 = /\s\-\-custom_user_agent/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string2 = /\sgenerate\saudit\s\-ep\s.{0,1000}\-\-passwords_in_userfile/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string3 = /\sgenerate\snormal\s\-ep\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-pf\s/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string4 = /\sgenerate\snormal\s\-ep\sex\-plan\.s365\s/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string5 = /\s\-\-random_user_agent/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string6 = /\s\-\-show_invalid_creds/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string7 = /\sspray\s\-ep\sex\-plan\.s365/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string8 = /\.py\sspray\s\-ep\s/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string9 = /\/spray\/spray\.py/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string10 = /\/Spray365/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string11 = /Spray365\.git/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string12 = /spray365\.py/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string13 = /spray365_results_.{0,1000}\.json/ nocase ascii wide
        // Description: Spray365 is a password spraying tool that identifies valid credentials for Microsoft accounts (Office 365 / Azure AD).
        // Reference: https://github.com/MarkoH17/Spray365
        $string14 = /\-\-user_file.{0,1000}\-\-password_file/ nocase ascii wide

    condition:
        any of them
}
