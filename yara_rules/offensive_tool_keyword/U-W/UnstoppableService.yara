rule UnstoppableService
{
    meta:
        description = "Detection patterns for the tool 'UnstoppableService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnstoppableService"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string1 = "\"ServiceName = \"\"unstoppable\"" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string2 = /\/UnstoppableService\.git/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string3 = /\\UnstoppableService\.csproj/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string4 = /\\UnstoppableService\.sln/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string5 = /\\UnstoppableService\-master/ nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string6 = "0C117EE5-2A21-496D-AF31-8CC7F0CAAA86" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string7 = "4889b9e1fa6c34ea86e56253135093b390919aa006f8cd3fa372b410f2f1e5bf" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string8 = "8e66227e48270913e40edcabdaa2d20332572f8ca6d066737e4ae3984d66b591" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string9 = "malcomvetter/UnstoppableService" nocase ascii wide
        // Description: a Windows service in C# that is self installing as a single executable and sets proper attributes to prevent an administrator from stopping or pausing the service through the Windows Service Control Manager interface
        // Reference: https://github.com/malcomvetter/UnstoppableService
        $string10 = /Provides\san\sunstoppable\sWindows\sService\sExperience\.\sLorem\sIpsum\sDolor/ nocase ascii wide

    condition:
        any of them
}
