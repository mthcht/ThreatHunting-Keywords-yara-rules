rule wafw00f
{
    meta:
        description = "Detection patterns for the tool 'wafw00f' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wafw00f"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: To do its magic. WAFW00F does the following Sends a normal HTTP request and analyses the response. this identifies a number of WAF solutions. If that is not successful. it sends a number of (potentially malicious) HTTP requests and uses simple logic to deduce which WAF it is. If that is also not successful. it analyses the responses previously returned and uses another simple algorithm to guess if a WAF or security solution is actively responding to our attacks.
        // Reference: https://github.com/EnableSecurity/wafw00f
        $string1 = /wafw00f/ nocase ascii wide

    condition:
        any of them
}
