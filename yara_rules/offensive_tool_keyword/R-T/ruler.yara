rule ruler
{
    meta:
        description = "Detection patterns for the tool 'ruler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ruler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string1 = /\sBruteForce\(/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string2 = /\sropbuffers\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string3 = /\sruler\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string4 = /\/http\-ntlm\/ntlmtransport/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string5 = /\/ntlmtransport\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string6 = /\/ropbuffers\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string7 = /\/rulerforms\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string8 = /\\ruler\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string9 = /autodiscover\/brute\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string10 = /ruler\-linux64/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string11 = /ruler\-linux86/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string12 = /ruler\-osx64/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string13 = /ruler\-win64\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string14 = /ruler\-win86\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string15 = /sensepost\/ruler/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string16 = /UserPassBruteForce/ nocase ascii wide

    condition:
        any of them
}