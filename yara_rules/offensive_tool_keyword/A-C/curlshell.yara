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
        $string1 = /\scurlshell\.py/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string2 = /\.py\s.{0,1000}0\.0\.0\.0.{0,1000}\-\-serve\-forever/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string3 = /\.py\s.{0,1000}\-\-dependabot\-workaround/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string4 = /\.py\s\-\-certificate\s.{0,1000}\.pem\s\-\-private\-key\s.{0,1000}\.pem\s\-\-listen\-port\s/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string5 = /\.py\s\-\-certificate\sfullchain\.pem\s\-\-private\-key\sprivkey\.pem\s\-\-listen\-port\s/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string6 = /\/curlshell\.git/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string7 = /\/curlshell\.git/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string8 = /\/curlshell\.py/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string9 = /\/curlshell\-main\./ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string10 = /\/curlshell\-main\// nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string11 = /\\curlshell\.py/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string12 = /\\curlshell\-main/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string13 = /\\curlshell\-main\\/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string14 = /b8285e421d702738eab45670ecae439a7228994e7068b04cb51740e47efbfb41/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string15 = /curl\shttps\:\/\/curlshell/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string16 = /curlshell\.py/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string17 = /https\:\/\/curlshell\:/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string18 = /https\:\/\/curlshell\:.{0,1000}\s\|\sbash/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string19 = /irsl\/curlshell/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string20 = /irsl\/curlshell/ nocase ascii wide

    condition:
        any of them
}
