rule _365_Stealer
{
    meta:
        description = "Detection patterns for the tool '365-Stealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "365-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string1 = /\s365\-Stealer\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string2 = /\s\-\-custom\-steal/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string3 = /\s\-\-custom\-steal\slistusers/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string4 = /\s\-\-custom\-steal\sonedrive/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string5 = /\s\-\-custom\-steal\sonenote/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string6 = /\s\-\-custom\-steal\soutlook/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string7 = /\sRedirect\sUrl\sAfter\sStealing\s\=\=\>\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string8 = /\/365\-Stealer\.git/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string9 = /\[\!\]\sLooks\slike\sVictim\s.{0,1000}\sdoesn\'t\shave\soffice365\sLicence\!/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string10 = /\[\!\]\sStealing\sprocesses\sdelayed\swith\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string11 = /\[\!\]\sSwithed\sto\scustom\sstealing\.\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string12 = /\[\+\]\sVictim\s.{0,1000}\shave\soffice365\sLicence\!/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string13 = /365\-Stealer\.py/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string14 = /365\-Stealer\-master/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string15 = /AlteredSecurity\/365\-Stealer/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string16 = /cscript\s\.\.\\\\temp\.vbs/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string17 = /\'Disable\sall\shttp\saccess\slogs\'/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string18 = /\'Host\sthe\sPhising\sApp\'/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string19 = /MIIEowIBAAKCAQEAvZtOCbMyFKJN3n89nctTfYLSeiCTNG01rAFl06hMkobyzr0c/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string20 = /o365\-Attack\-Toolkit/ nocase ascii wide

    condition:
        any of them
}
