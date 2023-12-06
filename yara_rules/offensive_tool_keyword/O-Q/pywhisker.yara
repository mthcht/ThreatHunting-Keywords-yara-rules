rule pywhisker
{
    meta:
        description = "Detection patterns for the tool 'pywhisker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywhisker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string1 = /\s\-u\s.{0,1000}\s\-d\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-k\s\-\-no\-pass\s\-\-target\s.{0,1000}\s\-\-action\s\"list\"/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string2 = /\.py\s\-d\s\"test\.local\"\s\-u\s\"john\"\s\-p\s\"password123\"\s\-\-target\s\"user2\"\s\-\-action\s\"list\"\s\-\-dc\-ip\s\"10\.10\.10\.1\"/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string3 = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\s.{0,1000}\s\-\-export\sPEM/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string4 = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\"add\"\s\-\-filename\s.{0,1000}\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string5 = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\"clear\".{0,1000}\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string6 = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\"info\"\s\-\-device\-id\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string7 = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\"list\"\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string8 = /\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-target\s.{0,1000}\s\-\-action\s\"remove\"\s\-\-device\-id\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string9 = /\/pywhisker\.git/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string10 = /getnthash\.py\s\-key\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string11 = /gettgtpkinit\.py\s\-cert\-pfx\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string12 = /Initializing\sdomainDumper\(\)/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string13 = /lmhash.{0,1000}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string14 = /pywhisker\.py/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string15 = /pywhisker\-main/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string16 = /ShutdownRepo\/pywhisker/ nocase ascii wide

    condition:
        any of them
}
