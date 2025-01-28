rule vscode
{
    meta:
        description = "Detection patterns for the tool 'vscode' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vscode"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string1 = /\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string2 = /\\\.vscode\-cli\\code_tunnel\.json/ nocase ascii wide
        // Description: the binary for the code-tunnels component is self-contained / portable and signed - seing it in different location than \Programs\Microsoft VS Code\bin\ is suspicious 
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string3 = /\\download\\code\-tunnel\.exe/ nocase ascii wide
        // Description: the binary for the code-tunnels component is self-contained / portable and signed - seing it in different location than \Programs\Microsoft VS Code\bin\ is suspicious 
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string4 = /\\ProgramData\\.{0,1000}\\code\-tunnel\.exe/ nocase ascii wide
        // Description: the binary for the code-tunnels component is self-contained / portable and signed - seing it in different location than \Programs\Microsoft VS Code\bin\ is suspicious 
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string5 = /\\temp\\code\-tunnel\.exe/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string6 = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string7 = /aue\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string8 = "code tunnel user login --access-token " nocase ascii wide
        // Description: Starts a reverse connection over global.rel.tunnels.api.visualstudio.com via websockets
        // Reference: https://badoption.eu/blog/2023/01/31/code_c2.html
        $string9 = /code\.exe\stunnel\s\-\-accept\-server\-license\-terms\s\-\-name\s/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string10 = /\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Starts a reverse connection over global.rel.tunnels.api.visualstudio.com via websockets
        // Reference: https://badoption.eu/blog/2023/01/31/code_c2.html
        $string11 = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string12 = /https\:\/\/.{0,1000}\..{0,1000}\.devtunnels\.ms/ nocase ascii wide

    condition:
        any of them
}
