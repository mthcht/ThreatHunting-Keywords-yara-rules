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
        $string1 = /.{0,1000}\s\-PipeName\s.{0,1000}\s\-ServiceName\s.{0,1000}\s\-Command\swhoami.{0,1000}/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string2 = /.{0,1000}\/Invoke\-SMBRemoting\.git.{0,1000}/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string3 = /.{0,1000}Enter\-SMBSession\s\-ComputerName\s.{0,1000}/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string4 = /.{0,1000}Enter\-SMBSession.{0,1000}\s\-PipeName\s.{0,1000}\s\-ServiceName\s.{0,1000}/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string5 = /.{0,1000}Invoke\-SMBRemoting\.ps1.{0,1000}/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string6 = /.{0,1000}Invoke\-SMBRemoting\-main.{0,1000}/ nocase ascii wide
        // Description: Interactive Shell and Command Execution over Named-Pipes (SMB)
        // Reference: https://github.com/Leo4j/Invoke-SMBRemoting
        $string7 = /.{0,1000}Leo4j\/Invoke\-SMBRemoting.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
