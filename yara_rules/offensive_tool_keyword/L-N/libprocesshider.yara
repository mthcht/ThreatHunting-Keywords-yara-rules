rule libprocesshider
{
    meta:
        description = "Detection patterns for the tool 'libprocesshider' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "libprocesshider"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string1 = /\sevil_script\.py/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string2 = /\slibprocesshider\.so\s/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string3 = "/bin/processhider" nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string4 = /\/evil_script\.py/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string5 = /\/libprocesshider\.git/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string6 = /\/libprocesshider\.so/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string7 = /\/processhider\.c/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string8 = /\\evil_script\.py/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string9 = "16d765e024adacabe84e9fd889030f5481546ef711bba0043e7e84eadd257d1a" nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string10 = "eb5fee1e402f321c8e705776faf2be7bbede5d2a24fe3ac40be082a75429f927" nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string11 = "gianlucaborello/libprocesshider" nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string12 = /https\:\/\/sysdig\.com\/blog\/hiding\-linux\-processes\-for\-fun\-and\-profit\// nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string13 = /sock\.send\(\\"\\"I\sAM\sA\sBAD\sBOY\\"\\"\)/ nocase ascii wide

    condition:
        any of them
}
