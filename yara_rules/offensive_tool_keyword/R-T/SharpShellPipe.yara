rule SharpShellPipe
{
    meta:
        description = "Detection patterns for the tool 'SharpShellPipe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShellPipe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string1 = /\/SharpShellPipe\.git/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string2 = /\\\\DCSC_stdInPipe/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string3 = /\\\\DCSC_stdOutPipe/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string4 = /43BB3C30\-39D7\-4B6B\-972E\-1E2B94D4D53A/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string5 = /DarkCoderSc\/SharpShellPipe/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string6 = /SharpShellPipe\.exe/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string7 = /SharpShellPipe\.sln/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string8 = /SharpShellPipe\-main/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string9 = /Successfully\sconnected.{0,1000}\sspawning\sshell\?/ nocase ascii wide

    condition:
        any of them
}
