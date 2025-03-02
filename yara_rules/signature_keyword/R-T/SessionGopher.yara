rule SessionGopher
{
    meta:
        description = "Detection patterns for the tool 'SessionGopher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionGopher"
        rule_category = "signature_keyword"

    strings:
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string1 = /Application\.Hacktool\.SessionGopher/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string2 = "ddbf3299675ffdd7e3475f8a4848f3ab6cdff8819348c75b9ac4d8fb76569a2c" nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string3 = /HackTool\.PS1\.SessionGopher/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string4 = "HTool-SessionGopher" nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string5 = /PowerShell\/HackTool\.SessionGopher/ nocase ascii wide

    condition:
        any of them
}
