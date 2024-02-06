rule WLAN_Windows_Passwords
{
    meta:
        description = "Detection patterns for the tool 'WLAN-Windows-Passwords' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WLAN-Windows-Passwords"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Opens PowerShell hidden - grabs wlan passwords - saves as a cleartext in a variable and exfiltrates info via Discord Webhook.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/WLAN-Windows-Passwords
        $string1 = /\sWindows\-Passwords\.ps1/ nocase ascii wide
        // Description: Opens PowerShell hidden - grabs wlan passwords - saves as a cleartext in a variable and exfiltrates info via Discord Webhook.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/WLAN-Windows-Passwords
        $string2 = /\/Windows\-Passwords\.ps1/ nocase ascii wide
        // Description: Opens PowerShell hidden - grabs wlan passwords - saves as a cleartext in a variable and exfiltrates info via Discord Webhook.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/WLAN-Windows-Passwords
        $string3 = /\\Windows\-Passwords\.ps1/ nocase ascii wide
        // Description: Opens PowerShell hidden - grabs wlan passwords - saves as a cleartext in a variable and exfiltrates info via Discord Webhook.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/WLAN-Windows-Passwords
        $string4 = /Invoke\-RestMethod\s\-ContentType\s\'Application\/Json\'\s\-Uri\s\$discord\s\-Method\sPost\s\-Body\s\(\$Body\s\|\sConvertTo\-Json\)/ nocase ascii wide
        // Description: Opens PowerShell hidden - grabs wlan passwords - saves as a cleartext in a variable and exfiltrates info via Discord Webhook.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/WLAN-Windows-Passwords
        $string5 = /netsh\swlan\sshow\sprofile\s\$wlan\skey\=clear\s\|\sSelect\-String\s.{0,1000}\?\<\=Key\sContent\\s\+\:\\s/ nocase ascii wide
        // Description: Opens PowerShell hidden - grabs wlan passwords - saves as a cleartext in a variable and exfiltrates info via Discord Webhook.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/WLAN-Windows-Passwords
        $string6 = /WLAN\-Windows\-Passwords\-Discord\-Exfiltration/ nocase ascii wide

    condition:
        any of them
}
