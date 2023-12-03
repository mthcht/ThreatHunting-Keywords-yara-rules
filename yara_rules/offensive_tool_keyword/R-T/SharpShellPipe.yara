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
        $string1 = /.{0,1000}\/SharpShellPipe\.git.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string2 = /.{0,1000}\\\\DCSC_stdInPipe.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string3 = /.{0,1000}\\\\DCSC_stdOutPipe.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string4 = /.{0,1000}43BB3C30\-39D7\-4B6B\-972E\-1E2B94D4D53A.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string5 = /.{0,1000}DarkCoderSc\/SharpShellPipe.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string6 = /.{0,1000}SharpShellPipe\.exe.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string7 = /.{0,1000}SharpShellPipe\.sln.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string8 = /.{0,1000}SharpShellPipe\-main.{0,1000}/ nocase ascii wide
        // Description: interactive remote shell access via named pipes and the SMB protocol.
        // Reference: https://github.com/DarkCoderSc/SharpShellPipe
        $string9 = /.{0,1000}Successfully\sconnected.{0,1000}\sspawning\sshell\?.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
