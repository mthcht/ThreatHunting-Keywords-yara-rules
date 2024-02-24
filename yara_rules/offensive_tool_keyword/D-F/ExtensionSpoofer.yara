rule ExtensionSpoofer
{
    meta:
        description = "Detection patterns for the tool 'ExtensionSpoofer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtensionSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string1 = /\sExtensionSpoof\.exe/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string2 = /\/ExtensionSpoof\.exe/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string3 = /\/ExtensionSpoofer\.git/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string4 = /\\ExtensionSpoof\.exe/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string5 = /\\ExtensionSpoof\.sln/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string6 = /\\ExtensionSpoofer\\/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string7 = /ExtensionSpoof\.vbproj/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string8 = /ExtensionSpoof\.xml/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string9 = /ExtensionSpoofer\-1\.zip/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string10 = /FCD5E13D\-1663\-4226\-8280\-1C6A97933AB7/ nocase ascii wide
        // Description: Spoof file icons and extensions in Windows
        // Reference: https://github.com/henriksb/ExtensionSpoofer
        $string11 = /henriksb\/ExtensionSpoofer/ nocase ascii wide

    condition:
        any of them
}
