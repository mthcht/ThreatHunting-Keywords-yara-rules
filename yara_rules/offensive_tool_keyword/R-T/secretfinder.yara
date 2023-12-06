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
        $string1 = /\.py\s.{0,1000}\s\-\-burp\s/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string2 = /\/SecretFinder\.git/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string3 = /BurpSuite\-SecretFinder/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string4 = /from\sburp\simport/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string5 = /import\sIBurpExtender/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string6 = /m4ll0k\/SecretFinder/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string7 = /SecretFinder\.py/ nocase ascii wide
        // Description: SecretFinder is a python script based on LinkFinder written to discover sensitive data like apikeys - accesstoken - authorizations - jwt..etc in JavaScript files
        // Reference: https://github.com/m4ll0k/SecretFinder
        $string8 = /SecretFinder\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
