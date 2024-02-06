rule shell
{
    meta:
        description = "Detection patterns for the tool 'shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string1 = /\/bin\/sh\s\|\snc/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string2 = /\/bin\/sh\s\-i\s\<\&3\s\>\&3\s2\>\&3/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string3 = /rm\s\-f\sbackpipe.{0,1000}\smknod\s\/tmp\/backpipe\sp\s\&\&\snc\s/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string4 = /sc\sconfig\sWinDefend\sstart\=\sdisabled/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string5 = /socket\(S.{0,1000}PF_INET.{0,1000}SOCK_STREAM.{0,1000}getprotobyname\(.{0,1000}tcp.{0,1000}\)\).{0,1000}if\(connect\(S.{0,1000}sockaddr_in\(\$p.{0,1000}inet_aton\(\$i\)\)\)\)/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string6 = /STDIN\-\>fdopen\(\$c.{0,1000}r\).{0,1000}\$\~\-\>fdopen\(\$c.{0,1000}w\).{0,1000}system\$_\swhile\<\>/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string7 = /uname\s\-a.{0,1000}\sw.{0,1000}\sid.{0,1000}\s\/bin\/bash\s\-i/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string8 = /schkconfig\soff\scbdaemon/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string9 = /service\scbdaemon\sstop/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string10 = /setenforce\s0/ nocase ascii wide

    condition:
        any of them
}
