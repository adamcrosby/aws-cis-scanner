# AWS CIS Benchmark Scanner

This scanner assesses your AWS Account for compliance with the [CIS Benchmark](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf) for AWS.  The content is using the Benchmark Version 1.0.0 - 02-29-2016.

An example output file is included at [report.html](report.html)

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public License. The link to the license terms can be found at https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

**This scanner currently only assesses US-EAST-1 Region.  It also features very little error checking or recovery, and works through checks linearly.**

**Please feel free to open issues (and include any output/stack trace), or submit PRs.**

**Finally, this was a project designed to help me learn the Go language, so, sorry if the code makes your eyes bleed, I'm sure it's highly non-idiomatic.**
