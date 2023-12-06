rule SentinelAgent
{
    meta:
        description = "Detection patterns for the tool 'SentinelAgent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SentinelAgent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string1 = /\sDumpS1\.ps1/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string2 = /\/DumpS1\.ps1/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string3 = /\\DumpS1\.ps1/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string4 = /\\temp\\__SentinelAgentKernel\.dmp/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string5 = /\\temp\\__SentinelAgentUser\.dmp/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string6 = /DumpProcessPid\s\-targetPID\s.{0,1000}\s\-outputFile/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string7 = /TakeDump\s\-SentinelHelper\s.{0,1000}\s\-ProcessId\s.{0,1000}\s\-User\s.{0,1000}\s\-Kernel\s/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string8 = /Trying\sto\sdump\sSentinelAgent\sto\s/ nocase ascii wide

    condition:
        any of them
}
