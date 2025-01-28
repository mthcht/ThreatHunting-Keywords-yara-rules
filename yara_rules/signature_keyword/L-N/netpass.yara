rule netpass
{
    meta:
        description = "Detection patterns for the tool 'netpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netpass"
        rule_category = "signature_keyword"

    strings:
        // Description: When you connect to a network share on your LAN or to your .NET Passport account. Windows allows you to save your password in order to use it in each time that you connect the remote server. This utility recovers all network passwords stored on your system for the current logged-on user. It can also recover the passwords stored in Credentials file of external drive. as long as you know the last log-on password.
        // Reference: https://www.nirsoft.net/utils/network_password_recovery.html
        $string1 = /HackTool\:Win32\/Netpasss\.AB\!MTB/ nocase ascii wide

    condition:
        any of them
}
