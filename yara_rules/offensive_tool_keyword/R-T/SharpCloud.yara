rule SharpCloud
{
    meta:
        description = "Detection patterns for the tool 'SharpCloud' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCloud"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string1 = /\/SharpCloud\.git/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string2 = /chrismaddalena\/SharpCloud/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string3 = /execute_assembly\sSharpCloud/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string4 = /sharpcloud\.cna/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string5 = /SharpCloud\.csproj/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string6 = /SharpCloud\.exe/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string7 = /SharpCloud\.sln/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string8 = /SharpCloud\-master/ nocase ascii wide

    condition:
        any of them
}
