rule SessionGopher
{
    meta:
        description = "Detection patterns for the tool 'SessionGopher' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionGopher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It has WMI functionality built in so it can be run remotely. Its best use case is to identify systems that may connect to Unix systems. jump boxes. or point-of-sale terminals.
        // Reference: https://github.com/Arvanaghi/SessionGopher
        $string1 = /SessionGopher/ nocase ascii wide

    condition:
        any of them
}
