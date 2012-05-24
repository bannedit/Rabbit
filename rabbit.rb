# Quick and agile debugging ;]

$:.unshift('.')
require 'lib/metasm/metasm'
require 'utils'

module Rabbit

	class Debugger
		include Rabbit::Utils # contains code for verbose printing
		include Rabbit::Symbols # code for symbol look ups

		def initialize
			@dbg = nil
			@pid = nil
			@cpu = Metasm::Ia32.new(32) # at the moment we're just testing on 32bit
			@breakpoints = {}
			@handlers = {
				Metasm::WinAPI::EXCEPTION_DEBUG_EVENT       => :handler_exception,
				Metasm::WinAPI::CREATE_PROCESS_DEBUG_EVENT  => :handler_newprocess,
				Metasm::WinAPI::CREATE_THREAD_DEBUG_EVENT   => :handler_newthread,
				Metasm::WinAPI::EXIT_PROCESS_DEBUG_EVENT    => :handler_endprocess,
				Metasm::WinAPI::EXIT_THREAD_DEBUG_EVENT     => :handler_endthread,
				Metasm::WinAPI::LOAD_DLL_DEBUG_EVENT        => :handler_loaddll,
				Metasm::WinAPI::UNLOAD_DLL_DEBUG_EVENT      => :handler_unloaddll,
				Metasm::WinAPI::OUTPUT_DEBUG_STRING_EVENT   => :handler_debugstring,
				Metasm::WinAPI::RIP_EVENT                   => :handler_rip
			}

			# check if we have debug privs
			if not Metasm::WinOS.get_debug_privilege
				abort "[error] - Failed to get debug privilege, quiting."
			end
		end

		def enable_bp(addr)
			return if not b = @breakpoint[addr]
			@cpu.dbg_enable_bp(self, addr, b)
			b.state = :enabled
			@breakpoints << {addr => "enabled"}
		end

		def disable_bp(addr)
			return if not b = @breakpoint[addr]
			@cpu.dbg_disable_bp(self, addr, b)
			b.state = :disabled
			@breakpoints << {addr => "disabled"}
		end

		def delete_bp(addr)
			@breakpoints.delete(addr)
		end

		def list_bps
			cnt = 0
			@breakpoints.each do |addr, status|
				puts "#{cnt} %08x - #{status}" % addr
				cnt += 1
			end
		end

		def set_handler(code, handler)
			if not @handlers.has_key?(code)
				puts "[error] - debug event code does not exist for custom handler"
				return false
			end

			if defined?(handler.to_sym.to_s) == "method"
				@handlers[code] = handler.to_sym
				return true
			else
				puts "[error] - custom handler method is not defined"
				return false
			end
		end

		def reset_handler(code)
			if not @handlers.has_key?(code)
				puts "[error] - cannot reset handler debug event code does not exist"
				return false
			end

			case code
			when Metasm::WinAPI::EXCEPTION_DEBUG_EVENT
				@handlers[Metasm::WinAPI::EXCEPTION_DEBUG_EVENT] = :handler_exception
			when Metasm::WinAPI::CREATE_PROCESS_DEBUG_EVENT
				@handlers[Metasm::WinAPI::CREATE_PROCESS_DEBUG_EVENT] = :handler_newprocess
			when Metasm::WinAPI::CREATE_THREAD_DEBUG_EVENT
				@handlers[Metasm::WinAPI::CREATE_THREAD_DEBUG_EVENT] = :handler_newthread
			when Metasm::WinAPI::EXIT_PROCESS_DEBUG_EVENT
				@handlers[Metasm::WinAPI::EXIT_PROCESS_DEBUG_EVENT] = :handler_endprocess
			when Metasm::WinAPI::EXIT_THREAD_DEBUG_EVENT
				@handlers[Metasm::WinAPI::EXIT_THREAD_DEBUG_EVENT] = :handler_endthread
			when Metasm::WinAPI::LOAD_DLL_DEBUG_EVENT
				@handlers[Metasm::WinAPI::LOAD_DLL_DEBUG_EVENT] = :handler_loaddll
			when Metasm::WinAPI::UNLOAD_DLL_DEBUG_EVENT
				@handlers[Metasm::WinAPI::UNLOAD_DLL_DEBUG_EVENT] = :handler_unloaddll
			when Metasm::WinAPI::OUTPUT_DEBUG_STRING_EVENT
				@handlers[Metasm::WinAPI::OUTPUT_DEBUG_STRING_EVENT] = :handler_debugstring
			when Metasm::WinAPI::RIP_EVENT
				@handlers[Metasm::WinAPI::RIP_EVENT] = :handler_rip
			end

			return true
		end

		def createproc(target, debug_child = false)
			flags = Metasm::WinAPI::DEBUG_PROCESS
			flags |= Metasm::WinAPI::DEBUG_ONLY_THIS_PROCESS if not debug_child
			startupinfo = [17*[0].pack('L').length, *([0]*16)].pack('L*')
			processinfo = [0, 0, 0, 0].pack('L*')

			if Metasm::WinAPI.createprocessa(nil, target, nil, nil, 0, flags, nil, nil, startupinfo, processinfo)
				pid = processinfo.unpack('LLL')[2]
			end
			@pid = pid
		end

		def load(target, debug_child = false)
			paths = ENV['PATH'].split(';')
			pid = nil
			exe = ""
			paths.each do |path|
				exe = path + "\\" + target
				if File.executable?(exe) # start the executable
					pid = self.createproc(exe, debug_child)
					break
				end
			end
			if not pid.nil?
				vprint "Created process #{exe} - #{pid}"
				@pid = pid
				@dbg = Metasm::WinDbgAPI.new(pid)
				@mem = @dbg.mem
				@hprocess = @dbg.hprocess
			else
				abort "[error] - Could not execute #{exe}."
			end
		end

		def attach(pid, debug_child = false)
			if pid.class == String
				# first check if the process is already running and get the pid if it is running
				exe = pid.split(File::SEPARATOR).last
				exe = exe.split("/").last
				proc = Metasm::WinOS.find_process(exe)

				if proc
					@pid = proc.pid
					vprint "Attaching to #{@pid} - #{exe} by name"
				end
				@dbg = Metasm::WinDbgAPI.new(@pid, debug_child)
				@mem = @dbg.mem
				@hprocess = @dbg.hprocess
			else
				proc = Metasm::WinOS.find_process(pid)
				if proc
					@pid = proc.pid
					exe = proc.modules.first.path
					vprint "Attaching to #{@pid} - #{exe} by pid"
					@dbg = Metasm::WinDbgAPI.new(@pid, debug_child)
					@mem = @dbg.mem
					@hprocess = @dbg.hprocess
				end
			end
		end

		def detach
			Metasm::WinAPI.debugactiveprocessstop(@pid)
			Metasm::WinAPI::DBG_CONTINUE
		end

		def run
			if not @dbg
				abort "Debugger could not attach to or execute a process"
			end

			@dbg.loop do |pid_, tid, code, info|
				case code
				when Metasm::WinAPI::EXCEPTION_DEBUG_EVENT
					send(@handlers[Metasm::WinAPI::EXCEPTION_DEBUG_EVENT], pid, tid, info)

				when Metasm::WinAPI::CREATE_PROCESS_DEBUG_EVENT
					send(@handlers[Metasm::WinAPI::CREATE_PROCESS_DEBUG_EVENT], pid, tid, info)

				when Metasm::WinAPI::CREATE_THREAD_DEBUG_EVENT
					send(@handlers[Metasm::WinAPI::CREATE_THREAD_DEBUG_EVENT], pid, tid, info)

				when Metasm::WinAPI::EXIT_PROCESS_DEBUG_EVENT
					send(@handlers[Metasm::WinAPI::EXIT_PROCESS_DEBUG_EVENT], pid, tid, info)

				when Metasm::WinAPI::EXIT_THREAD_DEBUG_EVENT
					send(@handlers[Metasm::WinAPI::EXIT_THREAD_DEBUG_EVENT], pid, tid, info)

				when Metasm::WinAPI::LOAD_DLL_DEBUG_EVENT
					send(@handlers[Metasm::WinAPI::LOAD_DLL_DEBUG_EVENT], pid, tid, info)

				when Metasm::WinAPI::UNLOAD_DLL_DEBUG_EVENT
					send(@handlers[Metasm::WinAPI::UNLOAD_DLL_DEBUG_EVENT], pid, tid, info)

				when Metasm::WinAPI::OUTPUT_DEBUG_STRING_EVENT
					send(@handlers[Metasm::WinAPI::OUTPUT_DEBUG_STRING_EVENT], pid, tid, info)

				when Metasm::WinAPI::RIP_EVENT
					send(@handlers[Metasm::WinAPI::RIP_EVENT], pid, tid, info)
				else
					handler_unknown(pid, tid, code, info)
				end
			end

			vprint "debugging session finished"
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
			status = "ModLoad: "
			Metasm::WinAPI::DBG_CONTINUE
		end

		def handler_unloaddll(pid, tid, info)
			Metasm::WinAPI::DBG_CONTINUE
		end

		def handler_endprocess(pid, tid, info)
			vprint "#{pid}:#{tid} process quit."
			prehandler_endprocess(pid, tid, info)
			Metasm::WinAPI::DBG_CONTINUE
		end

		def handler_newprocess(pid, tid, info)
			Metasm::WinAPI::DBG_CONTINUE
		end

		def handler_endthread(pid, tid, info)
			Metasm::WinAPI::DBG_CONTINUE
		end

		def handler_debugstring(pid, tid, info)
			Metasm::WinAPI::DBG_CONTINUE
		end

		def handler_rip(pid, tid, info)
			Metasm::WinAPI::DBG_EXCEPTION_NOT_HANDLED
		end

		def handler_unknown(pid, tid, code, info)
			Metasm::WinAPI::DBG_EXCEPTION_NOT_HANDLED
		end

	end

end