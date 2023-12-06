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
        $string1 = /\/PipeViewer\.exe/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string2 = /\/PipeViewer\.git/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string3 = /\/PipeViewer\.sln/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string4 = /\/PipeViewer\/Program\.cs/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string5 = /\\PipeViewer\.exe/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string6 = /\\PipeViewer\.sln/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string7 = /\\PipeViewer\\Program\.cs/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string8 = /2419CEDC\-BF3A\-4D8D\-98F7\-6403415BEEA4/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string9 = /cyberark\/PipeViewer/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string10 = /NamedPipeServer\.ps1/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string11 = /OLDNamedPipeServer\.ps1/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string12 = /PipeViewer\.csproj/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string13 = /PipeViewer_v1\.1\.zip/ nocase ascii wide
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string14 = /PipeViewer\-main/ nocase ascii wide

    condition:
        any of them
}
