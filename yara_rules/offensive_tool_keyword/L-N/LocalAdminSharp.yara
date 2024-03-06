rule LocalAdminSharp
{
    meta:
        description = "Detection patterns for the tool 'LocalAdminSharp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LocalAdminSharp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string1 = /\"localadmin123\!\"/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string2 = /\/LocalAdminSharp\.git/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string3 = /\/LocalAdminSharp\.sln/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string4 = /\\LocalAdminSharp\.sln/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string5 = /07628592\-5A22\-4C0A\-9330\-6C90BD7A94B6/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string6 = /LocalAdminSharp\.csproj/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string7 = /LocalAdminSharp\.exe/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string8 = /LocalAdminSharp\-main.{0,1000}\'/ nocase ascii wide
        // Description: .NET executable to use when dealing with privilege escalation on Windows to gain local administrator access
        // Reference: https://github.com/notdodo/LocalAdminSharp
        $string9 = /notdodo\/LocalAdminSharp/ nocase ascii wide

    condition:
        any of them
}
