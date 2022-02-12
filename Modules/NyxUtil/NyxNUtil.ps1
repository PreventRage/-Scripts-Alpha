$NyxNUtil_Code = Get-Content -Path '.\NyxNUtil.cs' -Raw
Add-Type -TypeDefinition $NyxNUtil_Code -PassThru
#$NyxNUtil_Type = Add-Type -TypeDefinition $NyxNUtil_Code -PassThru
#$NyxNUtil_Class = $NyxNUtil_Type[0]
