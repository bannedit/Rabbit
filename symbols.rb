require 'lib/metasm/metasm'

module Rabbit
	module Debug
		SYMOPT_CASE_INSENSITIVE = 0x00000001
		SYMOPT_UNDNAME          = 0x00000002
		SYMOPT_DEFERRED_LOADS   = 0x00000004
		SYMOPT_DEBUG            = 0x80000000
		SYMOPT_LOAD_LINES       = 0x00000010
		SYMOPT_NO_PROMPTS       = 0x00080000

		Metasm::WinAPI.new_api_c( 'WINBASEAPI HMODULE WINAPI LoadLibraryA( __in LPCSTR lpLibFileName );', 'kernel32')
		Metasm::WinAPI.new_api_c( 'WINBASEAPI LPVOID WINAPI GetProcAddress( __in HMODULE hModule, __in LPCSTR lpProcName );', 'kernel32')
		Metasm::WinAPI.new_api_c( 'WINBASEAPI DWORD WINAPI WaitForSingleObject( __in HANDLE hHandle, __in DWORD dwMilliseconds );', 'kernel32')
		Metasm::WinAPI.new_api_c( 'WINUSERAPI DWORD WINAPI WaitForInputIdle( __in HANDLE hProcess, __in DWORD dwMilliseconds );', 'user32')

		Metasm::WinAPI.new_api_c( 'typedef struct _SYMBOL_INFO {
		  ULONG   SizeOfStruct;
		  ULONG   TypeIndex;
		  DWORD64 Reserved1;
		  DWORD64 Reserved2;
		  ULONG   Index;
		  ULONG   Size;
		  DWORD64 ModBase;
		  ULONG   Flags;
		  DWORD64 Value;
		  DWORD64 Address;
		  ULONG   Register;
		  ULONG   Scope;
		  ULONG   Tag;
		  ULONG   NameLen;
		  ULONG   MaxNameLen;
		  CHAR    Name[1];
		} SYMBOL_INFO, *LPSYMBOL_INFO;', '.\\data\\dbghelp.dll' )

		Metasm::WinAPI.new_api_c('WINUSERAPI DWORD WINAPI SymGetOptions( VOID );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI BOOL WINAPI SymCleanup( __in HANDLE hProcess );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI DWORD WINAPI SymSetOptions( DWORD SymOptions );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI BOOL WINAPI SymInitialize( HANDLE hProcess, LPCSTR UserSearchPath, BOOL fInvadeProcess );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI BOOL WINAPI SymFromName( HANDLE hProcess, LPCSTR Name, __inout LPSYMBOL_INFO Symbol );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI DWORD64 WINAPI SymLoadModuleEx( HANDLE hProcess, HANDLE hFile, LPCSTR ImageName, LPCSTR ModuleName, DWORD64 BaseOfDll, DWORD DllSize, LPVOID Data, DWORD Flags );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI BOOL WINAPI SymFromAddr( __in HANDLE hProcess, __in DWORD64 Address, __out_opt DWORD64 * Displacement, __inout LPSYMBOL_INFO Symbol );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI BOOL WINAPI SymFromIndex( __in HANDLE hProcess, __in DWORD64 BaseOfDll, __in DWORD Index, __inout LPSYMBOL_INFO Symbol );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI BOOL WINAPI SymRefreshModuleList( __in HANDLE hProcess );', '.\\data\\dbghelp.dll' )
		Metasm::WinAPI.new_api_c('WINUSERAPI BOOL WINAPI SymSetSearchPath( __in HANDLE hProcess, __in_opt LPCSTR SearchPath );', '.\\data\\dbghelp.dll' )
		class Symbols
			def initialize(pid, handle)
				@handle = handle
				@pid = pid
				Metasm::WinAPI.loadlibrarya( ".\\data\\dbghelp.dll" )
				Metasm::WinAPI.loadlibrarya( ".\\data\\symsrv.dll" )
				@symbol_server = ENV['_NT_SYMBOL_PATH'] || "SRV*C:\\symbols*http://msdl.microsoft.com/download/symbols"

				symopts = Metasm::WinAPI.symgetoptions()
				symopts |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS
				Metasm::WinAPI.symsetoptions( symopts )

				Metasm::WinAPI.symsetsearchpath(handle, @symbol_server.dup)
				puts "Symbol search path is: #{@symbol_server}"
				Metasm::WinAPI.syminitialize( @handle, @symbol_server, true )
				# initialize symbols
			end

			def refresh_symbols
				Metasm::WinAPI.symrefreshmodulelist(@handle)
			end

			# ntdll!FunctionName -> address
			def resolve_symbol(sym)
				mod, func = sym.split('!')
			end

			def resolve_addr(address)
			end

			def addr_to_modoff(address)
			end
		end
	end
end