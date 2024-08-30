rule rmdir_
{
    meta:
        description = "Detection patterns for the tool 'rmdir ' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmdir "
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: removes files from the Recycle Bin - erasing forensic evidence
        // Reference: https://github.com/roadwy/DefenderYara/blob/9bbdb7f9fd3513ce30aa69cd1d88830e3cf596ca/Ransom/MSIL/Hakbit/Ransom_MSIL_Hakbit_PA_MTB.yar#L7
        $string1 = /rd\s\/s\s\/q\s\%systemdrive\%\\\$RECYCLE\.BIN/ nocase ascii wide

    condition:
        any of them
}
