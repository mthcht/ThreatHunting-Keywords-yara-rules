rule Invoke_PSImage
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PSImage' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PSImage"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Encodes a PowerShell script in the pixels of a PNG file and generates a oneliner to executenInvoke-PSImage takes a PowerShell script and encodes the bytes of the script into the pixels of a PNG image. It generates a oneliner for executing either from a file of from the web.
        // Reference: https://github.com/peewpw/Invoke-PSImage
        $string1 = /Invoke\-PSImage/ nocase ascii wide

    condition:
        any of them
}
