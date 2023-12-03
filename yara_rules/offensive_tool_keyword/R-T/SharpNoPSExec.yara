rule SharpNoPSExec
{
    meta:
        description = "Detection patterns for the tool 'SharpNoPSExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpNoPSExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string1 = /.{0,1000}\s\-\-target\=.{0,1000}\s\-\-payload\=.{0,1000}cmd\.exe\s\/c.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string2 = /.{0,1000}\/SharpNoPSExec.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string3 = /.{0,1000}\\SharpNoPSExec.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string4 = /.{0,1000}acf7a8a9\-3aaf\-46c2\-8aa8\-2d12d7681baf.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string5 = /.{0,1000}\-e\sZQBjAGgAbwAgAEcAbwBkACAAQgBsAGUAcwBzACAAWQBvAHUAIQA\=.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string6 = /.{0,1000}SharpNoPSExec\.csproj.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string7 = /.{0,1000}SharpNoPSExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string8 = /.{0,1000}SharpNoPSExec\.sln.{0,1000}/ nocase ascii wide
        // Description: Get file less command execution for lateral movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string9 = /.{0,1000}SharpNoPSExec\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
