Remove-Item -Path "\\Files\\PSRepository\NyxScripts.0.0.1.nupkg" -Force
Publish-Module -Path "$PSScriptRoot\NyxScripts" -Repository OurPSRepository