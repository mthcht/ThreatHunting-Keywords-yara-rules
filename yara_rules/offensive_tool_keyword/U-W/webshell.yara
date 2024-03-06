rule webshell
{
    meta:
        description = "Detection patterns for the tool 'webshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string1 = /\.php\?cmd\=cat\+\/etc\/passwd/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string2 = /\/perl\-reverse\-shell\.pl/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string3 = /\/php\-backdoor\.php/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string4 = /\/simple\-backdoor\.php/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string5 = /\\php\-backdoor\.php/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string6 = /\\simple\-backdoor\.php/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string7 = /Peaky\-XD\/webshell/ nocase ascii wide

    condition:
        any of them
}
