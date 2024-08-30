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
        $string1 = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string2 = /aue\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Starts a reverse connection over global.rel.tunnels.api.visualstudio.com via websockets
        // Reference: https://badoption.eu/blog/2023/01/31/code_c2.html
        $string3 = /code\.exe\stunnel\s\-\-accept\-server\-license\-terms\s\-\-name\s/ nocase ascii wide
        // Description: Starts a reverse connection over global.rel.tunnels.api.visualstudio.com via websockets
        // Reference: https://badoption.eu/blog/2023/01/31/code_c2.html
        $string4 = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string5 = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide

    condition:
        any of them
}
