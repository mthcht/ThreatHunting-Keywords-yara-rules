rule rdpv
{
    meta:
        description = "Detection patterns for the tool 'rdpv' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpv"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string1 = /\srdpv\.exe/ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string2 = /\/rdpv\.exe/ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string3 = /\/toolsdownload\/rdpv\.zip/ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string4 = /\\rdpv\.exe/ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string5 = /\>Password\sRecovery\sfor\sRemote\sDesktop\</ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string6 = /\>Remote\sDesktop\sPassView\</ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string7 = /205818e10c13d2e51b4c0196ca30111276ca1107fc8e25a0992fe67879eab964/ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string8 = /528de69797c36423a1e6b64fa8b1825f354e6707f2ca3760d81a9f58d69d58bb/ nocase ascii wide
        // Description: Remote Desktop PassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string9 = /RemoteDesktopPassView\.zip/ nocase ascii wide

    condition:
        any of them
}
