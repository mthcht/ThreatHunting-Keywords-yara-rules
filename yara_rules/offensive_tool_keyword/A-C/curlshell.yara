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
        $string1 = /.{0,1000}\.py\s.{0,1000}0\.0\.0\.0.{0,1000}\-\-serve\-forever.{0,1000}/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string2 = /.{0,1000}\.py\s.{0,1000}\-\-dependabot\-workaround.{0,1000}/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string3 = /.{0,1000}\.py\s\-\-certificate\s.{0,1000}\.pem\s\-\-private\-key\s.{0,1000}\.pem\s\-\-listen\-port\s.{0,1000}/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string4 = /.{0,1000}\/curlshell\.git.{0,1000}/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string5 = /.{0,1000}\\curlshell\-main.{0,1000}/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string6 = /.{0,1000}curlshell\.py.{0,1000}/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string7 = /.{0,1000}https:\/\/curlshell:.{0,1000}\s\|\sbash/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string8 = /.{0,1000}irsl\/curlshell.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
