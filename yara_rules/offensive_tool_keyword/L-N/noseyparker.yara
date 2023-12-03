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
        $string1 = /.{0,1000}\sgithub\srepos\slist\s\-\-org.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string2 = /.{0,1000}\sgithub\srepos\slist\s\-\-user\s.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string3 = /.{0,1000}\sscan\s\-\-github\-org.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string4 = /.{0,1000}\sscan\s\-\-github\-user.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string5 = /.{0,1000}\/noseyparker\.git.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string6 = /.{0,1000}noseyparker\sreport\s\-\-datastore\s.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string7 = /.{0,1000}noseyparker\sscan\s\-\-datastore\s.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string8 = /.{0,1000}noseyparker\ssummarize\s\-\-datastore\s.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string9 = /.{0,1000}noseyparker\-cli.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string10 = /.{0,1000}noseyparker\-main.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string11 = /.{0,1000}noseyparker\-v.{0,1000}\-universal\-macos.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string12 = /.{0,1000}noseyparker\-v.{0,1000}\-x86_64\-unknown\-linux\-gnu.{0,1000}/ nocase ascii wide
        // Description: Nosey Parker is a command-line program that finds secrets and sensitive information in textual data and Git history.
        // Reference: https://github.com/praetorian-inc/noseyparker
        $string13 = /.{0,1000}praetorian\-inc\/noseyparker.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
