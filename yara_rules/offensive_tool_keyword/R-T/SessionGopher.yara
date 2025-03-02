rule SessionGopher
{
    meta:
        description = "Detection patterns for the tool 'SessionGopher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionGopher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string1 = /\sSessionGopher\.ps1/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string2 = "\"Saved in session, but master password prevents plaintext recovery\"" nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string3 = /\$fct\s\=\sGet\-Content\s\-Encoding\sbyte\s\-Path\s/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string4 = /\/SessionGopher\.git/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string5 = /\/SessionGopher\.ps1/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string6 = /\\PuTTY\sppk\sFiles\.csv/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string7 = /\\SessionGopher\.ps1/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string8 = /\\SuperPuTTY\.csv/ nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string9 = "Arvanaghi/SessionGopher" nocase ascii wide
        // Description: uses WMI to extract saved session information for remote access tools such as WinSCP - PuTTY - SuperPuTTY - FileZilla and Microsoft Remote Desktop. It can be run remotely or locally.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string10 = "Invoke-SessionGopher" nocase ascii wide

    condition:
        any of them
}
