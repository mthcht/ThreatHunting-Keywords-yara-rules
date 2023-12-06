rule AWS_Loot
{
    meta:
        description = "Detection patterns for the tool 'AWS-Loot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AWS-Loot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string1 = /\sawsloot\.py/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string2 = /\.\/awsloot\s/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string3 = /\.\/awsloot\.py/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string4 = /\/AWS\-Loot/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string5 = /\/CodeBuildLooter\.py/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string6 = /\/EC2Looter\.py/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string7 = /\/LambdaLooter\.py/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string8 = /awsloot\.py\s/ nocase ascii wide

    condition:
        any of them
}
