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
        $string1 = /.{0,1000}\sDumpS1\.ps1.{0,1000}/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string2 = /.{0,1000}\/DumpS1\.ps1.{0,1000}/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string3 = /.{0,1000}\\DumpS1\.ps1.{0,1000}/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string4 = /.{0,1000}\\temp\\__SentinelAgentKernel\.dmp.{0,1000}/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string5 = /.{0,1000}\\temp\\__SentinelAgentUser\.dmp.{0,1000}/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string6 = /.{0,1000}DumpProcessPid\s\-targetPID\s.{0,1000}\s\-outputFile.{0,1000}/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string7 = /.{0,1000}TakeDump\s\-SentinelHelper\s.{0,1000}\s\-ProcessId\s.{0,1000}\s\-User\s.{0,1000}\s\-Kernel\s.{0,1000}/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string8 = /.{0,1000}Trying\sto\sdump\sSentinelAgent\sto\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
