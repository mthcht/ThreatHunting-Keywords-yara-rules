rule dev_tunnels
{
    meta:
        description = "Detection patterns for the tool 'dev-tunnels' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dev-tunnels"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string1 = /\shost\s\-p\s.*\s\-\-allow\-anonymous\s\-\-protocol\shttps/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string2 = /\.asse\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string3 = /\.exe\shost\s\-p\s.*\s\-\sallow\-anonymous/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string4 = /\.exe\sport\screate\s\-p\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string5 = /\-443\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string6 = /devtunnel\screate\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string7 = /devtunnel\shost\s\-p\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string8 = /devtunnel.*\suser\slogin\s\-/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string9 = /devtunnel\.exe\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string10 = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string11 = /https:\/\/.*\..*\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string12 = /https:\/\/.*\.brs\.devtunnels\.ms\// nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string13 = /https:\/\/.*\.euw\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string14 = /https:\/\/.*\.use\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string15 = /https:\/\/aka\.ms\/DevTunnelCliInstall/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string16 = /Microsoft\.DevTunnels\.Connections\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string17 = /Microsoft\.DevTunnels\.Contracts\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string18 = /Microsoft\.DevTunnels\.Management\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string19 = /Microsoft\.DevTunnels\.Ssh\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string20 = /Microsoft\.DevTunnels\.Ssh\.Tcp\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string21 = /ssh\s\@ssh\..*\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string22 = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string23 = /wss:\/\/.*\.tunnels\.api\.visualstudio\.com\/api\/v1\/Connect\// nocase ascii wide

    condition:
        any of them
}