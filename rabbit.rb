# Quick and agile debugging ;]
require 'lib/metasm/metasm'

module Rabbit

	class Debugger < Metasm::WinDbgAPI
		#include Rabbit::Utils # contains code for symbol look ups and various other useful stuff

		def initialize(target, debug_child = false)
			# check if we have debug privs
			if not Metasm::WinOS.get_debug_privilege
				puts("[error] - Failed to get debug privilege, quiting.")
				exit(-1)
			end

			# make sure target is passed properly
			if target.nil? or target.empty?
				puts Metasm::WinOS.list_processes.sort_by { |proc| proc.pid }
				abort 'target needed'
			end

			# check if target is a path if it is look for existing processes matching the process name and get the pid
			# if there is no pid start the process
			if target.class == String
				exe = target[ target.rindex('\\')+1, target.length-target.rindex('\\') ]
				proc = Metasm::WinOS.find_process(target)

				if proc
					@pid = proc.pid
				else # make sure that target is a path, create the process if its not already running (Taken from metasm WinDbgAPI code)
					if File.stat.executable?(target)
						flags = Metasm::WinAPI::DEBUG_PROCESS
						flags |= Metasm::WinAPI::DEBUG_ONLY_THIS_PROCESS if not debug_child
						startupinfo = [17*[0].pack('L').length, *([0]*16)].pack('L*')
						processinfo = [0, 0, 0, 0].pack('L*')
						Metasm::WinAPI.createprocessa(nil, target, nil, nil, 0, flags, nil, nil, startupinfo, processinfo)
						@pid = processinfo.unpack('LLL')[2]
					else
						puts("[error] - #{target} is not an executable file.")
						exit(-1)
					end
				end
			end

			# we should have a valid pid at this time
			@dbg = super(@pid, debug_child)
		end

		def detach
			Metasm::WinAPI.debugactiveprocessstop(@pid)
		end

		def handler_exception(pid, tid, info)
			ctx = get_context(pid, tid)
			regs = "eax: %08x ebx: %08x ecx: %08x edx: %08x esi: %08x edi: %08x\neip: %08x esp: %08x ebp: %08x" % 
				[ctx[:eax], ctx[:ebx], ctx[:ecx], ctx[:edx], ctx[:esi], ctx[:edi], ctx[:eip], ctx[:esp], ctx[:ebp]]

			exe = Metasm::ExeFormat.new(Metasm::Ia32.new)
			disasm = exe.cpu.decode_instruction( Metasm::EncodedData.new(@mem[pid][ctx[:eip], 16]), ctx[:eip] )

			case info.code
			when WinAPI::STATUS_ACCESS_VIOLATION
				status = "Access violation exception - #{info.code} "
				if info.nparam >= 1
					case info.info[0]
					when 0
						status << "- Read Operation"
					when 1
						status << "- Write Operation"
					when 8
						status << "- Execute Operation"
					end
				end

				puts regs
				puts disasm
				WinAPI::DBG_EXCEPTION_NOT_HANDLED

			when WinAPI::STATUS_BREAKPOINT
				status = "Break instruction exception - #{info.code} "
				puts regs
				puts disasm
				WinAPI::DBG_CONTINUE

			when WinAPI::STATUS_SINGLE_STEP
				# not yet implemented
				WinAPI::DBG_CONTINUE

			else
				# not yet implemented
				WinAPI::DBG_EXCEPTION_NOT_HANDLED
			end
		end

		def handler_loaddll(pid, tid, info)
		end

		def handler_unloaddll(pid, tid, info)
		end

		def handler_endprocess(pid, tid, info)
			puts "#{pid}:#{tid} process died"
			prehandler_endprocess(pid, tid, info)
			Metasm::WinAPI::DBG_CONTINUE
		end

	end

end