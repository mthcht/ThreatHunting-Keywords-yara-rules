rule lslsass
{
    meta:
        description = "Detection patterns for the tool 'lslsass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lslsass"
        rule_category = "signature_keyword"

    strings:
        // Description: dump active logon session password hashes from the lsass process (old tool for vista and older)
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string1 = /Hacktool\.PTHToolkit/ nocase ascii wide
        // Description: dump active logon session password hashes from the lsass process (old tool for vista and older)
        // Reference: https://www.virustotal.com/gui/file/b24ab1f8cb68547932dd8a5c81e9b2133763a7ddf48aa431456530c1340b939e/details
        $string2 = /HKTL_PTHTOOLKIT/ nocase ascii wide

    condition:
        any of them
}
