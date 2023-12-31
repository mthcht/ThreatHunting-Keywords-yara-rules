rule curlshell
{
    meta:
        description = "Detection patterns for the tool 'curlshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "curlshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string1 = /\.py\s.{0,1000}0\.0\.0\.0.{0,1000}\-\-serve\-forever/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string2 = /\.py\s.{0,1000}\-\-dependabot\-workaround/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string3 = /\.py\s\-\-certificate\s.{0,1000}\.pem\s\-\-private\-key\s.{0,1000}\.pem\s\-\-listen\-port\s/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string4 = /\/curlshell\.git/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string5 = /\\curlshell\-main/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string6 = /curlshell\.py/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string7 = /https:\/\/curlshell:.{0,1000}\s\|\sbash/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string8 = /irsl\/curlshell/ nocase ascii wide

    condition:
        any of them
}
