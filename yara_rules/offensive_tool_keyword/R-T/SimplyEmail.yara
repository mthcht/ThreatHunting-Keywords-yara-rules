rule SimplyEmail
{
    meta:
        description = "Detection patterns for the tool 'SimplyEmail' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimplyEmail"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SimplyEmail was built arround the concept that tools should do somthing. and do that somthing well. hence simply What is the simple email recon tool? This tool was based off the work of theHarvester and kind of a port of the functionality. This was just an expansion of what was used to build theHarvester and will incorporate his work but allow users to easily build Modules for the Framework. Which I felt was desperately needed after building my first module for theHarvester.
        // Reference: https://github.com/SimplySecurity/SimplyEmail
        $string1 = /\/SimplyEmail\.git/ nocase ascii wide
        // Description: SimplyEmail was built arround the concept that tools should do somthing. and do that somthing well. hence simply What is the simple email recon tool? This tool was based off the work of theHarvester and kind of a port of the functionality. This was just an expansion of what was used to build theHarvester and will incorporate his work but allow users to easily build Modules for the Framework. Which I felt was desperately needed after building my first module for theHarvester.
        // Reference: https://github.com/SimplySecurity/SimplyEmail
        $string2 = /SimplyEmail\.py/ nocase ascii wide
        // Description: SimplyEmail was built arround the concept that tools should do somthing. and do that somthing well. hence simply What is the simple email recon tool? This tool was based off the work of theHarvester and kind of a port of the functionality. This was just an expansion of what was used to build theHarvester and will incorporate his work but allow users to easily build Modules for the Framework. Which I felt was desperately needed after building my first module for theHarvester.
        // Reference: https://github.com/SimplySecurity/SimplyEmail
        $string3 = /SimplyEmail\-master/ nocase ascii wide
        // Description: SimplyEmail was built arround the concept that tools should do somthing. and do that somthing well. hence simply What is the simple email recon tool? This tool was based off the work of theHarvester and kind of a port of the functionality. This was just an expansion of what was used to build theHarvester and will incorporate his work but allow users to easily build Modules for the Framework. Which I felt was desperately needed after building my first module for theHarvester.
        // Reference: https://github.com/SimplySecurity/SimplyEmail
        $string4 = /SimplySecurity\/SimplyEmail/ nocase ascii wide

    condition:
        any of them
}
