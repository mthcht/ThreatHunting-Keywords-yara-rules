rule PipeViewer_
{
    meta:
        description = "Detection patterns for the tool 'PipeViewer ' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PipeViewer "
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string1 = /.{0,1000}\/PipeViewer\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string2 = /.{0,1000}\/PipeViewer\.git.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string3 = /.{0,1000}\/PipeViewer\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string4 = /.{0,1000}\/PipeViewer\/Program\.cs.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string5 = /.{0,1000}\\PipeViewer\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string6 = /.{0,1000}\\PipeViewer\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string7 = /.{0,1000}\\PipeViewer\\Program\.cs.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string8 = /.{0,1000}2419CEDC\-BF3A\-4D8D\-98F7\-6403415BEEA4.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string9 = /.{0,1000}cyberark\/PipeViewer.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string10 = /.{0,1000}NamedPipeServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string11 = /.{0,1000}OLDNamedPipeServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string12 = /.{0,1000}PipeViewer\.csproj.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string13 = /.{0,1000}PipeViewer_v1\.1\.zip.{0,1000}/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string14 = /.{0,1000}PipeViewer\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
