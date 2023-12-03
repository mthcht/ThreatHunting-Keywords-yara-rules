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
        $string1 = /.{0,1000}\/SharpCloud\.git.{0,1000}/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string2 = /.{0,1000}chrismaddalena\/SharpCloud.{0,1000}/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string3 = /.{0,1000}execute_assembly\sSharpCloud.{0,1000}/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string4 = /.{0,1000}sharpcloud\.cna.{0,1000}/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string5 = /.{0,1000}SharpCloud\.csproj.{0,1000}/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string6 = /.{0,1000}SharpCloud\.exe.{0,1000}/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string7 = /.{0,1000}SharpCloud\.sln.{0,1000}/ nocase ascii wide
        // Description: Simple C# for checking for the existence of credential files related to AWS - Microsoft Azure and Google Compute.
        // Reference: https://github.com/chrismaddalena/SharpCloud
        $string8 = /.{0,1000}SharpCloud\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
