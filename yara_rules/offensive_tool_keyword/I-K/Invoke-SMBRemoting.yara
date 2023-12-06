rule Invoke_SMBRemoting
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SMBRemoting' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SMBRemoting"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string1 = /\s\-PipeName\s.{0,1000}\s\-ServiceName\s.{0,1000}\s\-Command\swhoami/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string2 = /\/Invoke\-SMBRemoting\.git/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string3 = /Enter\-SMBSession\s\-ComputerName\s/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string4 = /Enter\-SMBSession.{0,1000}\s\-PipeName\s.{0,1000}\s\-ServiceName\s/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string5 = /Invoke\-SMBRemoting\.ps1/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string6 = /Invoke\-SMBRemoting\-main/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string7 = /Leo4j\/Invoke\-SMBRemoting/ nocase ascii wide

    condition:
        any of them
}
