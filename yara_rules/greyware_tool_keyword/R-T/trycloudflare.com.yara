rule trycloudflare_com
{
    meta:
        description = "Detection patterns for the tool 'trycloudflare.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "trycloudflare.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string1 = /\.trycloudfare\.com.{0,1000}DavWWWRoot/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string2 = /http\:\/\/.{0,1000}\.trycloudfare\.com/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string3 = /https\:\/\/.{0,1000}\.trycloudfare\.com/ nocase ascii wide
        // Description: Attackers abuse this service to expose malicious servers on a *.trycloudflare.com subdomain
        // Reference: https://lots-project.com/site/2a2e747279636c6f7564666c6172652e636f6d
        $string4 = /https\:\/\/.{0,1000}\.trycloudflare\.com/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string5 = /location\:\\\\.{0,1000}\.trycloudfare\.com/ nocase ascii wide
        // Description: The subdomain .trycloudflare.com is a temporary hostname provided by Cloudflare Tunnel - It allows users to expose local services to the internet without needing to configure port forwarding or a public IP - attackers frequently abuse it for malicious activities
        // Reference: https://www.forcepoint.com/blog/x-labs/asyncrat-python-trycloudflare-malware
        $string6 = /QNAME.{0,1000}\.trycloudfare\.com/ nocase ascii wide

    condition:
        any of them
}
