rule SharpNoPSExec
{
    meta:
        description = "Detection patterns for the tool 'SharpNoPSExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpNoPSExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string1 = /\s\-\-target\=.{0,1000}\s\-\-payload\=.{0,1000}cmd\.exe\s\/c/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string2 = /\/SharpNoPSExec/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string3 = /\\SharpNoPSExec/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string4 = /acf7a8a9\-3aaf\-46c2\-8aa8\-2d12d7681baf/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string5 = /\-e\sZQBjAGgAbwAgAEcAbwBkACAAQgBsAGUAcwBzACAAWQBvAHUAIQA\=/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string6 = /SharpNoPSExec\.csproj/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string7 = /SharpNoPSExec\.exe/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string8 = /SharpNoPSExec\.sln/ nocase ascii wide
        // Description: Get file less command execution for Lateral Movement.
        // Reference: https://github.com/juliourena/SharpNoPSExec
        $string9 = /SharpNoPSExec\-master/ nocase ascii wide

    condition:
        any of them
}
