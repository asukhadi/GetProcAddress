#include <windows.h>

DWORD GetProcAddress( HMODULE module, char* function )
{
	PIMAGE_DOS_HEADER dos_header = NULL;
	PIMAGE_NT_HEADERS nt_header = NULL;
	PIMAGE_EXPORT_DIRECTORY export = NULL;
	FARPROC* export_addr_table = NULL;
	char** export_name_table = NULL;
	WORD* export_ord_table = NULL;
	char* name = NULL;
	DWORD return_addr = 0;
	int i = 0;

	if( !module || !function ) 
		return NULL;

	dos_header = static_cast<PIMAGE_DOS_HEADER>( (void*)module );

	if( dos_header->e_magic == IMAGE_DOS_SIGNATURE && dos_header->e_lfanew != NULL ) 
	{
		nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>( (DWORD)module + dos_header->e_lfanew );

		if( nt_header->Signature == IMAGE_NT_SIGNATURE && nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 )
		{
			export = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( (DWORD)module + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
            
			export_addr_table = (FARPROC*)( (DWORD)module + export->AddressOfFunctions );
			export_name_table = (char**)( (DWORD)module + export->AddressOfNames );
			export_ord_table = (WORD*)( (DWORD)module + export->AddressOfNameOrdinals );

			for(i = 0; i < export->NumberOfNames; ++i)
			{
				name = (char*)( (DWORD)module + export_name_table[i] );

				if( !strcmp(name, function) )
				{
					return_addr = (DWORD)module + (DWORD)export_addr_table[export_ord_table[i]];
					break;
				}
			}
		}
	}

	return return_addr;
}