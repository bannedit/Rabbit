# Quick and agile debugging ;]

$:.unshift('.')
require 'lib/metasm/metasm'
require 'utils'

module Rabbit

	class Debugger < Metasm::WinDbgAPI
		include Rabbit::Utils # contains code for symbol look ups and various other useful stuff

		def initialize(target = nil, debug_child = false)
			# check if we have debug privs
			if not Metasm::WinOS.get_debug_privilege
				abort "[error] - Failed to get debug privilege, quiting."
			end

			# make sure target is passed properly
			if target.nil? or target.empty?
				puts Metasm::WinOS.list_processes.sort_by { |proc| proc.pid }
				abort "target needed"
			end

			if target.class == String
				# first check if the process is already running and get the pid if it is
				exe = target.split(File::SEPARATOR).last
				proc = Metasm::WinOS.find_process(exe)

				if proc
					@pid = proc.pid
					vprint "Attaching to #{@pid}"
				else
					if File.executable?(target) # this checks if the path leads to an exe
						pid = self.createproc(target, debug_child)
						if pid
							vprint "Created process #{target} - #{pid}"
						end
					else
						# lets see if the target exists in any of the PATH directories
						paths = ENV['PATH'].split(';')
						pid = nil
						paths.each do |path|
							exe = path + "\\" + target
							if File.executable?(exe) # start the executable
								pid = self.createproc(exe, debug_child)
								break
							end
						end
					end
					if not pid.nil?
						vprint "Created process #{exe} - #{pid}"
					else
						abort "[error] - Could not execute #{exe}."
					end
				end
			end

			# we should have a valid pid at this time
			@dbg = super(@pid, debug_child)
			loop
			vprint "debugging session finished"
		end

		def createproc(target, debug_child)
			flags = Metasm::WinAPI::DEBUG_PROCESS
			flags |= Metasm::WinAPI::DEBUG_ONLY_THIS_PROCESS if not debug_child
			startupinfo = [17*[0].pack('L').length, *([0]*16)].pack('L*')
			processinfo = [0, 0, 0, 0].pack('L*')

			if Metasm::WinAPI.createprocessa(nil, target, nil, nil, 0, flags, nil, nil, startupinfo, processinfo)
				pid = processinfo.unpack('LLL')[2]
			end
			@pid = pid
		end

		def detach
			Metasm::WinAPI.debugactiveprocessstop(@pid)
			Metasm::WinAPI::DBG_CONTINUE
		end

		def handler_exception(pid, tid, info)
			ctx = get_context(pid, tid)
			regs = "eax: %08x ebx: %08x ecx: %08x edx: %08x esi: %08x edi: %08x\neip: %08x esp: %08x ebp: %08x" % 
				[ctx[:eax], ctx[:ebx], ctx[:ecx], ctx[:edx], ctx[:esi], ctx[:edi], ctx[:eip], ctx[:esp], ctx[:ebp]]

			exe = Metasm::ExeFormat.new(Metasm::Ia32.new)
			inst = exe.cpu.decode_instruction( Metasm::EncodedData.new(@mem[pid][ctx[:eip], 16]), ctx[:eip])
			opcode = @mem[pid][ctx[:eip], inst.bin_length].to_s.unpack("H*")[0]

			disasm = "%08x\t%s\t%s" % [ctx[:eip], opcode, inst.instruction]

			case info.code
			when Metasm::WinAPI::STATUS_ACCESS_VIOLATION
				status = "Access violation exception - %08x " % info.code
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

				status_msg(status, regs, disasm)
				Metasm::WinAPI::DBG_EXCEPTION_NOT_HANDLED

			when Metasm::WinAPI::STATUS_BREAKPOINT
				status = "Break instruction exception - %08x " % info.code
				status_msg(status, regs, disasm)
				Metasm::WinAPI::DBG_CONTINUE

			when WinAPI::STATUS_SINGLE_STEP
				# not yet implemented
				Metasm::WinAPI::DBG_CONTINUE

			else
				# not yet implemented
				Metasm::WinAPI::DBG_EXCEPTION_NOT_HANDLED
			end
		end

		def handler_loaddll(pid, tid, info)
		end

		def handler_unloaddll(pid, tid, info)
		end

		def handler_endprocess(pid, tid, info)
			vprint "#{pid}:#{tid} process quit."
			prehandler_endprocess(pid, tid, info)
			Metasm::WinAPI::DBG_CONTINUE
		end

	end

end