rule noseyparker
{
    meta:
        description = "Detection patterns for the tool 'noseyparker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noseyparker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string1 = /\sgithub\srepos\slist\s\-\-org/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string2 = /\sgithub\srepos\slist\s\-\-user\s/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string3 = /\sscan\s\-\-github\-org/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string4 = /\sscan\s\-\-github\-user/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string5 = /\/noseyparker\.git/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string6 = /noseyparker\sreport\s\-\-datastore\s/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string7 = /noseyparker\sscan\s\-\-datastore\s/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string8 = /noseyparker\ssummarize\s\-\-datastore\s/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string9 = /noseyparker\-cli/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string10 = /noseyparker\-main/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string11 = /noseyparker\-v.{0,1000}\-universal\-macos/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string12 = /noseyparker\-v.{0,1000}\-x86_64\-unknown\-linux\-gnu/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string13 = /praetorian\-inc\/noseyparker/ nocase ascii wide

    condition:
        any of them
}
