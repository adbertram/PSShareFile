@{
	RootModule        = 'PSShareFile.psm1'
	ModuleVersion     = '0.3'
	GUID              = '00e3ed1b-85ea-4833-8ff1-f9fd7d3491ea'
	Author            = 'Adam Bertram'
	CompanyName       = 'TechSnips, LLC'
	Copyright         = '(c) 2018 Adam Bertram. All rights reserved.'
	Description       = 'A PowerShell module to manipulate various objects in Citrix''s ShareFile service'
	FunctionsToExport = '*'
	CmdletsToExport   = '*'
	VariablesToExport = '*'
	AliasesToExport   = '*'
	PrivateData       = @{
		PSData = @{
			Tags       = @('ShareFile')
			ProjectUri = 'https://github.com/adbertram/PSShareFile'
		}
	}
}