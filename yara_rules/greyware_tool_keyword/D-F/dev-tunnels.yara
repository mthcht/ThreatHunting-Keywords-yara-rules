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
        $string1 = /\shost\s\-p\s.{0,1000}\s\-\-allow\-anonymous\s\-\-protocol\shttps/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string2 = " host -p 443 -allow-anonymous" nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string3 = /\.asse\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string4 = /\.exe\shost\s\-p\s.{0,1000}\s\-\sallow\-anonymous/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string5 = /\.exe\sport\screate\s\-p\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string6 = /\\devtunnel\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string7 = /\\tunnel\-service\.log/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string8 = /\>devtunnel\.dll\</ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string9 = /\-443\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string10 = /asse\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string11 = /auc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string12 = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string13 = /brs\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string14 = "devtunnel create " nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string15 = "devtunnel host -p " nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string16 = "devtunnel user login" nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string17 = /devtunnel.{0,1000}\suser\slogin\s\-/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string18 = /devtunnel\.exe\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string19 = /devtunnel\.exe.{0,1000}host\s\-p\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string20 = /eun1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string21 = /euw\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string22 = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string23 = /https\:\/\/.{0,1000}\..{0,1000}\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string24 = /https\:\/\/.{0,1000}\.brs\.devtunnels\.ms\// nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string25 = /https\:\/\/.{0,1000}\.euw\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string26 = /https\:\/\/.{0,1000}\.use\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string27 = /https\:\/\/aka\.ms\/DevTunnelCliInstall/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string28 = /https\:\/\/aka\.ms\/TunnelsCliDownload\// nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string29 = /inc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string30 = /Microsoft\.DevTunnels\.Connections\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string31 = /Microsoft\.DevTunnels\.Contracts\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string32 = /Microsoft\.DevTunnels\.Management\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string33 = /Microsoft\.DevTunnels\.Ssh\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string34 = /Microsoft\.DevTunnels\.Ssh\.Tcp\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string35 = /ssh\s\@ssh\..{0,1000}\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string36 = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string37 = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string38 = /uks1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string39 = /use\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string40 = /use2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string41 = /usw2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string42 = /usw3\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string43 = /wss\:\/\/.{0,1000}\.tunnels\.api\.visualstudio\.com\/api\/v1\/Connect\// nocase ascii wide

    condition:
        any of them
}
