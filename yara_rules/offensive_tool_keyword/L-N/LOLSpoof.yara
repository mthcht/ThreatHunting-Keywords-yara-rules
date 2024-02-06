rule LOLSpoof
{
    meta:
        description = "Detection patterns for the tool 'LOLSpoof' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string1 = /\/lolbin\.exe/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string2 = /\/LOLSpoof\.git/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string3 = /\/LOLSpoof\.nim/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string4 = /\[LOLSpoof\]\s\>\s/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string5 = /\\lolbin\.exe/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string6 = /\\LOLSpoof\.nim/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string7 = /\\LOLSpoof\\/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string8 = /An\sinteractive\sshell\sto\sspoof\ssome\sLOLBins/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string9 = /Could\snot\sspoof\sbinary\:\s/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string10 = /itaymigdal\/LOLSpoof/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string11 = /lolbin\.exe\s/ nocase ascii wide
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string12 = /LOLSpoof\.exe/ nocase ascii wide

    condition:
        any of them
}
