rule WebSocketReverseShellDotNet
{
    meta:
        description = "Detection patterns for the tool 'WebSocketReverseShellDotNet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebSocketReverseShellDotNet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string1 = /\/reverseShell\-1\.0\.1\-zip\.zip/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string2 = ":8070/reverseShellClients" nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string3 = /\\BrowserExfelterator\.cs/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string4 = /\\commands\\CameraScreenShot\.cs/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string5 = /\\DiscordTokenExfilterater\.cs/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string6 = /\\Obfuscar\.Console\.exe/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string7 = /\\PersistsMalware\.cs/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string8 = /\\TokenExfiltereter\.cs/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string9 = ">Obfuscar Console Utility<" nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string10 = "44782077d86a1fd173b94e020c23dc511a58fe77e055116014c30f8ecc4ead91" nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string11 = "474B99B7-66C4-4AC2-8AD3-065DD13DDDFF" nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string12 = "543111f63af0bba0de982e608dde5289571d227b941c74131a8b9df9a8dc2609" nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string13 = "950bb21485106b135bbe1e28b8b7f74652cadeb9ae8c68342f0ee8c91ce8306c" nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string14 = /c2\-server\.mtattab\.com\/reverseShellClients/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string15 = /http\:\/\/127\.0\.0\.1\:8070/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string16 = /password\-hijaker\.exe/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string17 = "RemoteShellCodeInjection-master" nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string18 = /RemoteShellCodeInjection\-master\.zip/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string19 = /schtasks\s\/create\s\/tn\s.{0,1000}Constants\.PERSISTENCE_WINDOWS_TASK\s\+/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string20 = "WebSocketReverseShellDotNet" nocase ascii wide

    condition:
        any of them
}
