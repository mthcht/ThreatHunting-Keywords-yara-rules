rule ServerlessRedirector
{
    meta:
        description = "Detection patterns for the tool 'ServerlessRedirector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ServerlessRedirector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string1 = /\/ServerlessRedirector\.git/ nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string2 = /C2FunctionAgent/ nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string3 = /https\:\/\/C2_SERVER_IP\// nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string4 = /KINGSABRI\/ServerlessRedirector/ nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string5 = /ServerlessRedirector\-main/ nocase ascii wide

    condition:
        any of them
}
