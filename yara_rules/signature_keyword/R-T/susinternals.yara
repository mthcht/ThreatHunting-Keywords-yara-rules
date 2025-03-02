rule susinternals
{
    meta:
        description = "Detection patterns for the tool 'susinternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "susinternals"
        rule_category = "signature_keyword"

    strings:
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string1 = /HEUR\:HackTool\.Python\.Impacket\.gen/ nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string2 = /VirTool\:Python\/RemoteSvcExecute\.A/ nocase ascii wide

    condition:
        any of them
}
