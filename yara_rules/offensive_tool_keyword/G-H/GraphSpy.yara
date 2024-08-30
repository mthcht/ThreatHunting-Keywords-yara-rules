rule GraphSpy
{
    meta:
        description = "Detection patterns for the tool 'GraphSpy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphSpy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string1 = /\sGraphSpy\.py/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string2 = /\/GraphSpy\.git/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string3 = /\/GraphSpy\.py/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string4 = /\\GraphSpy\.py/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string5 = /\\GraphSpy\-master/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string6 = /\]\sStarting\sGraphSpy\.\sOpen\sin\syour\sbrowser\sby\sgoing\sto\sthe\surl\sdisplayed\sbelow\./ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string7 = /app\.config\[\'graph_spy_db_folder\'\]/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string8 = /app\.config\[\'graph_spy_db_path\'\]/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string9 = /f0037d99bc3119fc613d304af20599e8c791b1c99208d5d452a01738777f7b49/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string10 = /graphspy\s\-i\s/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string11 = /GraphSpy\.GraphSpy\:main/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string12 = /graphspy\.py\s\-i\s/ nocase ascii wide
        // Description: Initial Access and Post-Exploitation Tool for AAD and O365 with a browser-based GUI
        // Reference: https://github.com/RedByte1337/GraphSpy
        $string13 = /RedByte1337\/GraphSpy/ nocase ascii wide

    condition:
        any of them
}
