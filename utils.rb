module Rabbit
	module Utils
		def status_msg(*args)
			puts args
		end

		def vprint(*args)
			puts args if verbose
		end
	end
end