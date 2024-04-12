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
        $string2 = /\:8070\/reverseShellClients/ nocase ascii wide
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
        $string6 = /\\gcloud\\application_default_credentials\.json/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string7 = /\\Obfuscar\.Console\.exe/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string8 = /\\PersistsMalware\.cs/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string9 = /\\TokenExfiltereter\.cs/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string10 = /\>Obfuscar\sConsole\sUtility\</ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string11 = /44782077d86a1fd173b94e020c23dc511a58fe77e055116014c30f8ecc4ead91/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string12 = /474B99B7\-66C4\-4AC2\-8AD3\-065DD13DDDFF/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string13 = /543111f63af0bba0de982e608dde5289571d227b941c74131a8b9df9a8dc2609/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string14 = /950bb21485106b135bbe1e28b8b7f74652cadeb9ae8c68342f0ee8c91ce8306c/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string15 = /c2\-server\.mtattab\.com\/reverseShellClients/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string16 = /http\:\/\/127\.0\.0\.1\:8070/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string17 = /password\-hijaker\.exe/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string18 = /RemoteShellCodeInjection\-master/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string19 = /RemoteShellCodeInjection\-master\.zip/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string20 = /schtasks\s\/create\s\/tn\s.{0,1000}Constants\.PERSISTENCE_WINDOWS_TASK\s\+/ nocase ascii wide
        // Description: A .NET-based Reverse Shell, it establishes a link to the command and control for subsequent guidance.
        // Reference: https://github.com/The-Hustler-Hattab/WebSocketReverseShellDotNet
        $string21 = /WebSocketReverseShellDotNet/ nocase ascii wide

    condition:
        any of them
}
