local function main()
	
	--������ arg[1]Ϊ��ͼ, arg[2]Ϊ����·��
	if (not arg) or (#arg < 2) then
		print('[����]: �뽫��ͼ�϶���check.bat�Ͻ��м���')
	end
	
	local input_map  = arg[1]
	local root_dir   = arg[2]
	
	--����require��Ѱ·��
	package.path = package.path .. ';' .. root_dir .. 'src\\?.lua'
	package.cpath = package.cpath .. ';' .. root_dir .. 'build\\?.dll'
	require 'luabind'
	require 'filesystem'
	require 'utility'

	--����·��
	local input_map    = fs.path(input_map)
	local root_dir     = fs.path(root_dir)

	--��ͼ��
	local map_name = input_map:filename():string():sub(1, -5)
	
	local test_dir     = root_dir / 'test'
	local log_dir      = root_dir / 'log' / os.date('%Y.%m.%d')
	local map_log_dir  = log_dir / ('[' .. os.date('%H.%M.%S') .. ']' .. map_name .. '.txt')

	fs.remove_all(test_dir)
	fs.create_directories(test_dir)

	fs.create_directories(log_dir)

	--����log
	local f_log = io.open(map_log_dir:string(), 'w')
	
	local oldprint = print
	
	function print(...)
		f_log:write(('[%.3f]%s\n'):format(os.clock(), table.concat({...}, '%t')))
		return oldprint(...)
	end
	
	print('[��ͼ]: ' .. map_name)

	--У���ļ���
		--����ļ�������
		if #map_name > 27 then
			print('[����]: �ļ�������,���ܴ���27���ַ�: ' .. #map_name)
			return true
		else
			print('[ͨ��]: �ļ�������Ϊ: ' .. #map_name)
		end

		--����Ƿ�����Ƿ��ַ�
			local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._0123456789()'
			--��������
			local t = {}
			for i = 1, #chars do
				t[chars:sub(i, i)] = true
			end

			for i = 1, #map_name do
				if not t[map_name:sub(i, i)] then
					print('[����]: �ļ��������Ƿ��ַ�: ' .. map_name:sub(i, i))
					return true
				end
			end
			print('[ͨ��]: �ļ�������ʹ��')

	--�򿪵�ͼ
	local inmap = mpq_open(input_map)
	if inmap then
		print('[�ɹ�]: �� ' .. input_map:string())
	else
		print('[����]: �� ' .. input_map:string() .. ' ,��������ͷ?')
		return true
	end
	
	--��Ҫ�������ļ�
	local list_file = {
		{'(listfile)', '(listfile)'},
		{'war3map.w3i', 'war3map.w3i'},
		{'scripts\\war3map.j', 'war3map.j'},
		{'war3map.j', 'war3map.j'},
	}

	--������Щ�ļ�
	for _, t in ipairs(list_file) do
		local mpq_name, file_name = t[1], t[2]
		local file_dir = test_dir / file_name
		if inmap:extract(mpq_name, file_dir) then
			print('[�ɹ�]: ���� ' .. mpq_name)
		else
			print('[ʧ��]: ���� ' .. mpq_name)
		end
	end

	--�رյ���ͼ
	inmap:close()

	--��ȡj�ļ���w3i�ļ�
	local f_j = io.open((test_dir / 'war3map.j'):string(), 'r')
	local f_w3i = io.open((test_dir / 'war3map.w3i'):string(), 'rb')
	local j, w3i
	if f_j then
		j = f_j:read('*a')
		f_j:close()
		print('[�ɹ�]: ��j�ļ�')
	else
		print('[����]: û���ҵ�j�ļ�')
		return true
	end
	if f_w3i then
		w3i = f_w3i:read('*a')
		f_w3i:close()
		print('[�ɹ�]: ��w3i�ļ�')
	else
		print('[����]: û���ҵ�w3i�ļ�')
		return true
	end

	--�������
		--���ע��ű�ʽ����
			local mod = false
			--����޸ĺۼ�(ͨ��listfile)
				local f_listfile = io.open((test_dir / '(listfile)'):string(), 'r')
				if f_listfile then
					local listfile = f_listfile:read('*a')
					f_listfile:close()
					if listfile:match('war3map.j') then
						print('[����]: �����޸ĺۼ�,�����н�һ�����')
						mod = true
					end
				end

			--����޸ĺۼ�(ͨ��������)
				local chars = {'\t', '    ', 'hke_', 'efl_', '_feiba', 'WCDTOF', 'ou99_'}
				for _, char in ipairs(chars) do
					if j:match(char) then
						print('[����]: ���ֿ��ɴ���,�����н�һ�����')
						mod = true
						break
					end
				end

			--���н�һ�����
			if mod then
				local ss = {} --��ſ��ɴ���
				local lines = {} --����
				local count = 0 --���'\t'��'    '�ļ���
				for line in io.lines((test_dir / 'war3map.j'):string()) do
					table.insert(lines, line)
					if line:match('\t') or line:match('    ') then
						count = count + 1
					end
				end

				if count / #lines > 0.5 then
					print('[ע��]: ��ͼ�ű�����û�н����Ż�: ' .. (count / #lines))
					table.remove(chars, 1)
					table.remove(chars, 1)
				elseif count / #lines > 0.1 then
					print('[ע��]: ���ִ����Ʊ�����ո�,���ֶ�����ͼ�Ƿ���й��Ż�: ' .. (count / #lines))
				end

				for _, line in ipairs(lines) do
					for _, char in ipairs(chars) do
						local x = line:find(char)
						if x and (x == 1 or (char ~= '\t' and char ~= '    ')) then
							print(('[%s]: %s'):format(char, line))
							table.insert(ss, line)
							break
						end
					end
				end

				local funcs = {
					{'CreateTrigger', '����������'},
					{'CreateTimer', '������ʱ��'},
					{'TimerStart', '������ʱ��'},
					{'StartTimer', '������ʱ��'},
					{'AddItem', '������Ʒ'},
					{'SetItem', '������Ʒ'},
					{'EventPlayerChatString', '������Ϣ'},
					{'FogMaskEnable', '�������'},
					{'FogEnable', '�������'},
					{'UnitResetCooldown', '������ȴ'},
					{'SetHero', '����Ӣ��'},
					{'SetUnit', '���õ�λ'},
					{'SetPlayer', '�������'},
					{'PlayerState', '�������'},
					{'UnitAddAbility', '���Ӽ���'},
					{'Dialog', '�Ի���'},
					{'TriggerRegister', 'ע�ᴥ����'},
					{'TriggerAdd', 'ע�ᴥ����'},
					{'_GOLD', '��ҽ�Ǯ'},
					{'_LUMBER', '���ľ��'},
					{'_LIFE', '��λ����'},
					{'_MANA', '��λ����'},
				}

				local cheats = table.new(0)
				local cheat_count = 0

				for x = 1, #ss do
					local script = ss[x]
					for y = 1, #funcs do
						local word, reason = funcs[y][1], funcs[y][2]
						if script:match(word) then
							cheats[reason] = cheats[reason] + 1
							cheat_count = cheat_count + 1
						end
					end
				end

				if #ss > 0 and cheat_count > 0 then
					local cheat_result = {}
					for name, count in pairs(cheats) do
						table.insert(cheat_result, name .. ': ' .. count)
					end
					print(('[����]: ���ֿ��ɵ����д���,��ͼ���ܰ������״���\n\t�������: %d\n\t%s\n\t����: %s'):format(#ss, table.concat(cheat_result, '\n\t'), cheat_count))
					return true
				else
					print('[ͨ��]: δ���ֿ��ɵ����д���')
				end
			end

		--���InitCustomPlayerSlots,InitCustomTeams,InitAllyPriorities��3�������Ƿ񱻻���
			--�ҵ�ָ��������
			local f_config = j:match("function%s+config%s+takes%s+nothing%s+returns%s+nothing(.-)endfunction")
			--�ȼ���Ƿ��к���
			if (f_config:match('SetPlayerRacePreference') or j:match('%sInitCustomPlayerSlots%s') or not j:match('SetPlayerRacePreference'))
			and (f_config:match('PLAYER_STATE_ALLIED_VICTORY') or j:match('%sInitCustomTeams%s') or not j:match('PLAYER_STATE_ALLIED_VICTORY'))
			and (f_config:match('SetStartLocPrioCount') or j:match('%sInitAllyPriorities%s') or not j:match('SetStartLocPrioCount')) then
				print('[ͨ��]: �ҵ���ָ��config����')
			else
				print('[����]: config����������')
				return true
			end

		--���w3i�ļ���j�ļ��Ķ��������Ƿ�ƥ��
			--��¼j�ļ��еĶ�������
				local j_players, j_teams, j_player_control, j_player_team, f_now = 0, 0, {}, table.new(0)
				do
					--����tonumber,Ϊ���Ǹ�����ʮ������
					local oldtonumber = tonumber

					local function tonumber(e, b)
						local flag
						if e:sub(1, 1) == '$' then
							flag = true
							e = e:sub(2)
						elseif e:sub(1, 2) == '0x' then
							flag = true
							e = e:sub(3)
						end
						if flag then
							local char = '123456789ABCDEF'
							local char2 = table.new(0)
							for i = 1, #char do
								char2[char:sub(i, i)] = i
								char2[char:sub(i, i):lower()] = i
							end
							local r = 0
							local q = 1
							for i = #e, 1, -1 do
								r = r + char2[e:sub(i, i)] * q
								q = q * 16
							end
							e = r
						end
						return oldtonumber(e, b)
					end
					
					j_players = math.min(12, tonumber(f_config:match('SetPlayers.-([%$%w]+)')))
					j_teams = math.min(12, tonumber(f_config:match('SetTeams.-([%$%w]+)')))
					
					f_now = f_config:match('InitCustomPlayerSlots') and j:match("function%s+InitCustomPlayerSlots%s+takes%s+nothing%s+returns%s+nothing(.-)endfunction") or f_config
					for i, t in f_now:gmatch('SetPlayerController.-Player.-([%$%w]+).-([%u_]+)') do
						i= tonumber(i)
						j_player_control[i] = t
					end
				
					f_now = f_config:match('InitCustomTeams') and j:match("function%s+InitCustomTeams%s+takes%s+nothing%s+returns%s+nothing(.-)endfunction") or f_config
					for i, t in f_now:gmatch('SetPlayerTeam.-Player.-([%$%w]+).-([%$%w]+)') do
						i, t = tonumber(i), tonumber(t)
						j_player_team[i] = t
					end
				end

				print('[�ɹ�]: ����j�ļ��е��������')

			--��¼w3i�ļ��еĶ�������
				local w3i_players, w3i_teams, w3i_player_control, w3i_player_team, w3i_now = 0, 0, {}, table.new(0)

				local function w3i_addTeam(players, x)
					--print(players, x)
					for i = 11, 0, -1 do
						if players >= 2 ^ i then
							players = players - 2 ^ i
							w3i_player_team[i] = x
							--print(i)
						end
					end
				end
				
				--�ҵ�������õ�ƫ��
				local x, y, byte = w3i:find(string.char(0xff) .. '(%Z)%z%z%z.%z%z%z.%z%z%z.%z%z%z.%z%z%z%Z-%z')
				w3i_players = tonumber(byte:byte())
				
				--�����￪ʼ���������
				w3i_now = w3i:sub(x + 5)

				local controls = {
					'MAP_CONTROL_USER',
					'MAP_CONTROL_COMPUTER',
					'MAP_CONTROL_NEUTRAL',
					'MAP_CONTROL_RESCUABLE',
				}
				--ƥ����ҿ�����
				local x = -1
				for i, t, name in w3i_now:gmatch('(.)%z%z%z(.)%z%z%z.%z%z%z.%z%z%z(%Z-)%z................') do
					i, t = i:byte(), t:byte()
					if i > x then
						w3i_player_control[i] = controls[t]
						x = i
					end
				end

				--ƥ�������Ϣ
					x = 0
					--�ȴ�����һ��������Ϣ,�Ƚ�����
					local _, y, teams, w1, w2, teamname = w3i_now:find('(.)%z%z%z.%z%z%z(.)(.)' .. string.char(0xff, 0xff) .. '(%Z-)%z')
					w3i_teams = teams:byte()
					local players = (w1:byte() + w2:byte() * 0x100) - 0xf000
					w3i_addTeam(players, x)
					--��ʼ��������Ķ���,����еĻ�
					if w3i_teams > 1 then
						--�����￪ʼ�Ǻ���Ķ�������
						w3i_now = w3i_now:sub(y + 1)
						for w1, w2 in w3i_now:gmatch('.%z%z%z(.)(.)..%Z-%z') do
							x = x + 1
							if x >= w3i_teams then
								break
							end
							local players = (w1:byte() + w2:byte() * 0x100)
							w3i_addTeam(players, x)
						end
					end

					print('[�ɹ�]: ����w3i�ļ��е��������')

			--��ʼ�Ա�j��w3i
			print('[�ɹ�]: ��ʼ�Ա�j�ļ���w3i�ļ��е��������')

			if j_players ~= w3i_players then
				print(('[����]: ���������ƥ��(%s - %s)'):format(j_players, w3i_players))
				return true
			end

			--[[
			---�����teams,��Ϊconfig�����е�SetTeams��׼ȷ
			if j_teams ~= w3i_teams then
				print(('[����]: ����������ƥ��(%s - %s)'):format(j_teams, w3i_teams))
				return true
			end
			--]]

			for i = 0, 11 do
				if j_player_control[i] ~= w3i_player_control[i] then
					print(('[����]: ��ҿ����߲�ƥ��(���%s:%s - %s)'):format(i, j_player_control[i], w3i_player_control[i]))
					return true
				end

				if j_player_team[i] ~= w3i_player_team[i] and j_player_control[i] then
					print(('[����]: ��Ҷ��鲻ƥ��(���%s:%s - %s)'):format(i, j_player_team[i], w3i_player_team[i]))
					return true
				end
			end

		print('[ͨ��]: j�ļ���w3i�ļ��е��������ƥ��')
	--���
	print('[ͨ��]: ��ͼ������,��ʱ ' .. os.clock() .. ' ��')
	
end

if main() then
end