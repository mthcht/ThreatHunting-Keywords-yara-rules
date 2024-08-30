rule PipeViewer_
{
    meta:
        description = "Detection patterns for the tool 'PipeViewer ' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PipeViewer "
        rule_category = "signature_keyword"

    strings:
        // Description: A tool that shows detailed information about named pipes in Windows
        // Reference: https://github.com/cyberark/PipeViewer
        $string1 = /Trojan\:Win32\/Malagent\!MSR/ nocase ascii wide

    condition:
        any of them
}
