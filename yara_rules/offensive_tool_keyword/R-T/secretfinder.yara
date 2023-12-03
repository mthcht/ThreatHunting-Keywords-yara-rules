rule secretfinder
{
    meta:
        description = "Detection patterns for the tool 'secretfinder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "secretfinder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string1 = /.{0,1000}\.py\s.{0,1000}\s\-\-burp\s.{0,1000}/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string2 = /.{0,1000}\/SecretFinder\.git.{0,1000}/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string3 = /.{0,1000}BurpSuite\-SecretFinder.{0,1000}/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string4 = /.{0,1000}from\sburp\simport.{0,1000}/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string5 = /.{0,1000}import\sIBurpExtender.{0,1000}/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string6 = /.{0,1000}m4ll0k\/SecretFinder.{0,1000}/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string7 = /.{0,1000}SecretFinder\.py.{0,1000}/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string8 = /.{0,1000}SecretFinder\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
