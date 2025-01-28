rule netpass
{
    meta:
        description = "Detection patterns for the tool 'netpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netpass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string1 = /\/utils\/network_password_recovery\.html/ nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string2 = "17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180" nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string3 = "17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180" nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string4 = "60724a25dd319ec57b77e16c52e52a09c7b82ed4ea38dab6d6c2e880dcebb439" nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string5 = /f\:\\temp\\pass\.html/ nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string6 = /netpass\.exe/ nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string7 = /netpass\.zip/ nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string8 = /netpass_x64\.exe/ nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string9 = /netpass\-x64\.zip/ nocase ascii wide
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string10 = "Network Password Recovery v" nocase ascii wide

    condition:
        any of them
}
