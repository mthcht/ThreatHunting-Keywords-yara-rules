rule SecretServerSecretStealer
{
    meta:
        description = "Detection patterns for the tool 'SecretServerSecretStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecretServerSecretStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string1 = /\sLocal\:DPAPIDecrypt/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string2 = /\sLocal\:LoadEncryptionDll/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string3 = /\sSecretStealer\.ps1/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string4 = /\s\-WebRoot\sC\:\\inetpub\\wwwroot\\SecretServer/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string5 = /\/SecretServerSecretStealer\.git/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string6 = /\/SecretServerSecretStealer\-master\.zip/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string7 = /\/SecretStealer\.ps1/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string8 = /\/thycotic_secretserver_dump\.rb/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string9 = /\\SecretStealer\.ps1/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string10 = /\\Thycotic\.ihawu\.EncryptionProtection_x64\.dll/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string11 = /\\Thycotic\.ihawu\.EncryptionProtection_x86\.dll/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string12 = /\\thycotic_secretserver_dump\.rb/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string13 = /a36e3489d4317d70fd2cb100020b0c53d575988b790ec33c4c4d204e5e834016/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string14 = /aes.{0,1000}83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string15 = /denandz\/SecretServerSecretStealer/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string16 = /Encryption\.config\svalues\sare\sencrypted\swith\sDPAPI\,\sdecrypting/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string17 = /Invoke\-SecretDecrypt/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string18 = /Invoke\-SecretStealer/ nocase ascii wide
        // Description: Powershell script that decrypts the data stored within a Thycotic Secret Server
        // Reference: https://github.com/denandz/SecretServerSecretStealer
        $string19 = /xor.{0,1000}8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e/ nocase ascii wide

    condition:
        any of them
}
