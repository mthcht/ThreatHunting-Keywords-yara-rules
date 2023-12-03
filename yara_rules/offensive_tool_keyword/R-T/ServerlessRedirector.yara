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
        $string1 = /.{0,1000}\/ServerlessRedirector\.git.{0,1000}/ nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string2 = /.{0,1000}C2FunctionAgent.{0,1000}/ nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string3 = /.{0,1000}https:\/\/C2_SERVER_IP\/.{0,1000}/ nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string4 = /.{0,1000}KINGSABRI\/ServerlessRedirector.{0,1000}/ nocase ascii wide
        // Description: Serverless Redirector in various cloud vendor for red team
        // Reference: https://github.com/KINGSABRI/ServerlessRedirector
        $string5 = /.{0,1000}ServerlessRedirector\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
