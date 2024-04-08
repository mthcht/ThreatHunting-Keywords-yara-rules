rule persistence_demos
{
    meta:
        description = "Detection patterns for the tool 'persistence_demos' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "persistence_demos"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string1 = /\/persistence_demos\.git/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string2 = /\:\\ProgramData\\demo\.dll/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string3 = /\[\-\]\sCOM\sHijacking\sfailed\!/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string4 = /\[\-\]\sDropping\sDLL\sfailed\!/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string5 = /\[\-\]\sHijacking\sfailed\!/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string6 = /\[\+\]\sCOM\sHijacked\!/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string7 = /\[\+\]\sDLL\sdropped\!/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string8 = /\\ext_hijacker\.h/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string9 = /\\hijacker_app\\src\\ProxyApp\.exe/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string10 = /\\persistence_demos\-master/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string11 = /hasherezade\/persistence_demos/ nocase ascii wide
        // Description: Demos of various (also non standard) persistence methods used by malware
        // Reference: https://github.com/hasherezade/persistence_demos
        $string12 = /Hello\,\syou\shave\sbeen\spwned\!/ nocase ascii wide

    condition:
        any of them
}
