rule LOLSpoof
{
    meta:
        description = "Detection patterns for the tool 'LOLSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLSpoof"
        rule_category = "signature_keyword"

    strings:
        // Description: An interactive shell to spoof some LOLBins command line
        // Reference: https://github.com/itaymigdal/LOLSpoof
        $string1 = "ATK/LOLSpoof-A" nocase ascii wide

    condition:
        any of them
}
