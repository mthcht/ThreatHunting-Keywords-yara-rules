rule glit
{
    meta:
        description = "Detection patterns for the tool 'glit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "glit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string1 = /\srepo\s\-u\shttps\:\/\/github\.com\// nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string2 = /\/glit\.git/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string3 = /\/glit\-cli/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string4 = /\/glit\-core/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string5 = /\\glit\.exe/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string6 = /\\glit\-cli/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string7 = /cargo\sinstall\sglit/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string8 = /glit\sorg\s\-/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string9 = /glit\srepo\s/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string10 = /glit\suser\s/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string11 = /glit\.exe\sorg/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string12 = /glit\.exe\srepo/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string13 = /glit\.exe\suser/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string14 = /glit\-i686\-pc\-windows\-msvc/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string15 = /glit\-main\.zip/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string16 = /glit\-x86_64\-apple\-darwin/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string17 = /glit\-x86_64\-pc\-windows\-msvc/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string18 = /glit\-x86_64\-unknown\-linux\-gnu/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string19 = /shadawck\/glit/ nocase ascii wide

    condition:
        any of them
}
