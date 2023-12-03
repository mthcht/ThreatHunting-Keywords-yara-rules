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
        $string1 = /.{0,1000}\sBruteForce\(.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string2 = /.{0,1000}\sropbuffers\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string3 = /.{0,1000}\sruler\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string4 = /.{0,1000}\/http\-ntlm\/ntlmtransport.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string5 = /.{0,1000}\/ntlmtransport\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string6 = /.{0,1000}\/ropbuffers\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string7 = /.{0,1000}\/rulerforms\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string8 = /.{0,1000}\\ruler\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string9 = /.{0,1000}autodiscover\/brute\.go.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string10 = /.{0,1000}ruler\-linux64.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string11 = /.{0,1000}ruler\-linux86.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string12 = /.{0,1000}ruler\-osx64.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string13 = /.{0,1000}ruler\-win64\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string14 = /.{0,1000}ruler\-win86\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string15 = /.{0,1000}sensepost\/ruler.{0,1000}/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string16 = /.{0,1000}UserPassBruteForce.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
