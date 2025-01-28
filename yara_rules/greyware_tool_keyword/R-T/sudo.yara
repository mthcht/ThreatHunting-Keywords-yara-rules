rule sudo
{
    meta:
        description = "Detection patterns for the tool 'sudo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: sudo on windows allowing privilege escalation
        // Reference: https://www.tiraniddo.dev/2024/02/sudo-on-windows-quick-rundown.html
        $string1 = /\.server_DoElevationRequest\(\(Get\-NtProcess\s\-ProcessId\s\$pid\).{0,1000}\\"cmd\.exe\\".{0,1000}C\:\\\\"/
        // Description: sudo on windows allowing privilege escalation
        // Reference: https://www.tiraniddo.dev/2024/02/sudo-on-windows-quick-rundown.html
        $string2 = /Connect\-RpcClient\s.{0,1000}\s\-EndpointPath\ssudo_elevate_4652/
        // Description: Sudo Persistence via sudoers file
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /echo\s.{0,1000}\%sudo\s\sALL\=\(ALL\)\sNOPASSWD\:\sALL.{0,1000}\s\>\>\s\/etc\/sudoers/
        // Description: access sensitive files by abusing sudo permissions
        // Reference: N/A
        $string4 = "sudo apache2 -f /etc/shadow"
        // Description: abusing LD_LIBRARY_PATH sudo option  to escalade privilege
        // Reference: N/A
        $string5 = /sudo\sLD_LIBRARY_PATH\=\.\sapache2/
        // Description: abusinf LD_PREDLOAD option to escalade privilege
        // Reference: N/A
        $string6 = /sudo\sLD_PRELOAD\=\/tmp\/preload\.so\sfind/

    condition:
        any of them
}
