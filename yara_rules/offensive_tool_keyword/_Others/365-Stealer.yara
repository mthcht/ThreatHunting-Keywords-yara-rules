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
        $string1 = /.{0,1000}\s365\-Stealer\s.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string2 = /.{0,1000}\s\-\-custom\-steal/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string3 = /.{0,1000}\s\-\-custom\-steal\slistusers.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string4 = /.{0,1000}\s\-\-custom\-steal\sonedrive.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string5 = /.{0,1000}\s\-\-custom\-steal\sonenote.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string6 = /.{0,1000}\s\-\-custom\-steal\soutlook.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string7 = /.{0,1000}\sRedirect\sUrl\sAfter\sStealing\s\=\=\>\s.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string8 = /.{0,1000}\/365\-Stealer\.git.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string9 = /.{0,1000}\[\!\]\sLooks\slike\sVictim\s.{0,1000}\sdoesn\'t\shave\soffice365\sLicence\!.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string10 = /.{0,1000}\[\!\]\sStealing\sprocesses\sdelayed\swith\s.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string11 = /.{0,1000}\[\!\]\sSwithed\sto\scustom\sstealing\.\s.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string12 = /.{0,1000}\[\+\]\sVictim\s.{0,1000}\shave\soffice365\sLicence\!.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string13 = /.{0,1000}365\-Stealer\.py.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string14 = /.{0,1000}365\-Stealer\-master.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string15 = /.{0,1000}AlteredSecurity\/365\-Stealer.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string16 = /.{0,1000}cscript\s\.\.\\\\temp\.vbs.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string17 = /.{0,1000}\'Disable\sall\shttp\saccess\slogs\'.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string18 = /.{0,1000}\'Host\sthe\sPhising\sApp\'.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string19 = /.{0,1000}MIIEowIBAAKCAQEAvZtOCbMyFKJN3n89nctTfYLSeiCTNG01rAFl06hMkobyzr0c.{0,1000}/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string20 = /.{0,1000}o365\-Attack\-Toolkit.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
