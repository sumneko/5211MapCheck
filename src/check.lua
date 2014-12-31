local function main()
	
	--������ arg[1]Ϊ��ͼ, arg[2]Ϊ����·��
	if (not arg) or (#arg < 2) then
		print('[����]: �뽫��ͼ�϶���check.bat�Ͻ��м���')
		return
	end
	
	local input_map  = arg[1]
	local root_dir   = arg[2]
	
	--���require��Ѱ·��
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

	local fail
	
	--У���ļ���
		--����ļ�������
		local enable = true
		if #map_name > 27 then
			print('[����]: �ļ�������,���ܴ���27���ַ�: ' .. #map_name)
			fail = true
		else
			print('[ͨ��]: �ļ�������Ϊ: ' .. #map_name)
		end

		--����Ƿ�����Ƿ��ַ�
			local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._0123456789'
			--��������
			local t = {}
			for i = 1, #chars do
				t[chars:sub(i, i)] = true
			end

			local ws = {}
			for i = 1, #map_name do
				if not t[map_name:sub(i, i)] then
					table.insert(ws, map_name:sub(i, i))
				end
			end

			if #ws > 0 then
				print('[����]: �ļ��������Ƿ��ַ�: ' .. table.concat(ws))
				fail = true
				enable = false
			end
			
			if map_name:find('  ') then
				print('[����]: �ļ������ܰ���2�������Ŀո�')
				fail = true
				enable = false
			end

			if map_name:find('%D%.') or map_name:find('%.%D') then
				print('[����]: С����ǰ�����������')
				fail = true
				enable = false
			end
			
			if enable then
				print('[ͨ��]: �ļ�������ʹ��')
			end

	--ȥ���ļ���ֻ������
	if 0 == bit32.band(input_map:permissions(nil), 128) then		
		input_map:permissions(bit32.bor(0x1000, 128))
	end

	--�򿪵�ͼ
	local inmap = mpq_open(input_map)
	if inmap then
		print('[�ɹ�]: �� ' .. input_map:string())
	else
		print('[����]: �� ' .. input_map:string() .. ' ,�ļ���ռ�û��������ͷ?')
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
			local ss = {} --��ſ��ɴ���
			--����޸ĺۼ�(ͨ��listfile)
				local f_listfile = io.open((test_dir / '(listfile)'):string(), 'r')
				if f_listfile then
					local listfile = f_listfile:read('*a')
					f_listfile:close()
					if listfile:match('war3map.j') then
						print('[����]: �����޸ĺۼ�,�����н�һ�����')
						mod = true
					end
					listfile = listfile:lower()
					--[[
					if listfile:match('loading') or listfile:match('screen') then
						print('=================================================')
						print('[����]: �����滻������ͼ')
						print('=================================================')
					end
					--]]
				end

			--����޸ĺۼ�(ͨ��InitTrig����˳��)
				local trg_funcs = {}
				local trg_inits = {}

				for name in j:gmatch('function InitTrig_(%S-) takes') do
					table.insert(trg_funcs, name)
				end

				for name in j:gmatch('call InitTrig_(%C-)%(%)') do
					table.insert(trg_inits, name)
				end

				local funcs = {}
				local x, y = 1, 1
				while trg_funcs[x] and trg_inits[y] do
					if trg_funcs[x] ~= trg_inits[y] then
						local func1, func2 = trg_funcs[x], trg_inits[y]
						if func1 then
							for i = y, #trg_inits do
								if func1 == trg_inits[i] then
									for j = y, i - 1 do
										table.insert(funcs, trg_inits[j])
									end
									y = i
								end
							end
						else
							for i = x, #trg_funcs do
								if func2 == trg_funcs[i] then
									for j = x, i - 1 do
										table.insert(funcs, trg_funcs[j])
									end
									x = i
									break
								end
							end
						end
					end
					x = x + 1
					y = y + 1
				end

				if #funcs ~= 0 then
					print('[����]: ���ֿ��ɺ���,�����н�һ�����')
					for _, name in ipairs(funcs) do
						funcs[name] = true
						funcs['InitTrig_' .. name] = true
						funcs['Trig_' .. name .. 'Actions'] = true
						funcs['Trig_' .. name .. 'Conditions'] = true
						funcs['Trig_' .. name .. '_Actions'] = true
						funcs['Trig_' .. name .. '_Conditions'] = true
					end
					for name, content in j:gmatch('function (%S-) takes(.-)endfunction') do
						if funcs[name] then
							content = ('function %s takes%s'):format(name, content)
							for line in content:gmatch('([^\n\r]+)') do
								print(('[%s]: %s\n'):format('ע��', line))
								table.insert(ss, line)
							end
						end
					end
				end
				
				
			--����޸ĺۼ�(ͨ��main�����ײ��Ƿ��д����ж�)
				local text = j:match('%cendglobals(.-)function main takes')
				if text and #text > 50 then
					local main_func = j:match('function main takes nothing returns nothing(.-)endfunction')
					local call_funcs = {}
					for func in main_func:gmatch('call (.-)%(') do
						table.insert(call_funcs, func)
					end

					local funcs_finded = {InitGlobals = 2, InitCustomTriggers = 2, RunInitializationTriggers = 2, TriggerAddAction = 0, ExecuteFunc = 0, CreateDestructableZ = 0}
					local check_stack

					if not j:match('function RunInitializationTriggers takes') then
						funcs_finded.ConditionalTriggerExecute = 2
					end
					
					function check_stack(func)
						if funcs_finded[func] then
							return funcs_finded[func]
						end

						if func:sub(1, 9) == 'InitTrig_' then
							return 1
						end
						
						funcs_finded[func] = 1
						local func_text = text:match('(function ' .. func .. ' takes.-endfunction)')
						if func_text then
							for func in func_text:gmatch('[^%c%w_]([%w_]-)%(') do
								if check_stack(func) == 2 then
									return 2
								end
							end
							for func in func_text:gmatch('function ([%w_]-)%)') do
								if check_stack(func) == 2 then
									return 2
								end
							end
							for line in func_text:gmatch('([^\n\r]+)') do
								print(('[%s]: %s\n'):format('ע��', line))
								table.insert(ss, line)
								mod	= true
							end
							return
						end
						return 0
					end
					
					for i = #call_funcs, 1, -1 do
						local func_name = call_funcs[i]
						if check_stack(func_name) == 2 or check_stack(func_name) == 0 then
							break
						end
					end
				end

			--����޸ĺۼ�(ͨ��������)
				local chars = {'\t', '    ', 'hke_', 'efl_', '_feiba', 'WCDTOF', 'ou99_', '55you'}

			--��̬���������
				local v_name = j:match('string%s+(%a+)%C-Hke')
				if v_name then
					print('[����]: ����HKE�ؼ���')
					table.insert(chars, v_name)
				end
				
				for _, char in ipairs(chars) do
					if j:match(char) then
						print('[����]: ���ֿ��ɴ���,�����н�һ�����')
						mod = true
						break
					end
				end
			
			--���н�һ�����
			if mod then
				local lines = {} --����
				local count = 0 --���'\t'��'    '�ļ���
				for line in io.lines((test_dir / 'war3map.j'):string()) do
					table.insert(lines, line)
					if line:match('\t') or line:match('    ') or line:match('//') then
						count = count + 1
					end
				end

				if count / #lines > 0.25 then
					print('[ע��]: ��ͼ�ű�����û�н����Ż�: ' .. (count / #lines))
					table.remove(chars, 1)
					table.remove(chars, 1)
				elseif count / #lines > 0.05 then
					print('[ע��]: ���ִ����Ʊ����ո�,���ֶ�����ͼ�Ƿ���й��Ż�: ' .. (count / #lines))
				else
					--�����ͬ�Ĵ���
					for i, line in ipairs(lines) do
						local char	= line:match '[^.][%w_]+%s+([%w_]+)%s+%=[^%=]'
						if char and char:sub(1, 1):match '%D' then
							print(('[ע��]: ���ֿ��ɱ���: (%s)[%s]%s'):format(i, char, line))
							table.insert(chars, '%W' .. char .. '%W')
						end
					end
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
					{'AddItem', '�����Ʒ'},
					{'SetItem', '������Ʒ'},
					{'EventPlayerChatString', '������Ϣ'},
					{'FogMaskEnable', '�������'},
					{'FogEnable', '�������'},
					{'UnitResetCooldown', '������ȴ'},
					{'SetHero', '����Ӣ��'},
					{'SetUnit', '���õ�λ'},
					{'SetPlayer', '�������'},
					{'PlayerState', '�������'},
					{'UnitAddAbility', '��Ӽ���'},
					{'Dialog', '�Ի���'},
					{'TriggerRegister', 'ע�ᴥ����'},
					{'TriggerAdd', 'ע�ᴥ����'},
					{'_GOLD', '��ҽ�Ǯ'},
					{'_LUMBER', '���ľ��'},
					{'_LIFE', '��λ����'},
					{'_MANA', '��λ����'},
					{'PingMinimap', '��ǵ�ͼ'}
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
					fail = true
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
				fail = true
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
					--�ȴ����һ��������Ϣ,�Ƚ�����
					local _, y, teams, w1, w2, teamname = w3i_now:find('(.)%z%z%z.%z%z%z(.)(.)' .. string.char(0xff, 0xff) .. '(%Z-)%z')
					w3i_teams = teams:byte()
					local players = (w1:byte() + w2:byte() * 0x100) - 0xf000
					w3i_addTeam(players, x)
					--��ʼ�������Ķ���,����еĻ�
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
			local enable = true
			if j_players ~= w3i_players then
				print(('[����]: ���������ƥ��(%s[j] - %s[w3i])'):format(j_players, w3i_players))
				fail = true
				enable = false
			end

			--[[
			---�����teams,��Ϊconfig�����е�SetTeams��׼ȷ
			if j_teams ~= w3i_teams then
				print(('[����]: ����������ƥ��(%s[j] - %s[w3i])'):format(j_teams, w3i_teams))
				fail = true
			end
			--]]

			for i = 0, 11 do
				if j_player_control[i] ~= w3i_player_control[i] then
					print(('[����]: ��ҿ����߲�ƥ��(���%s:%s[j] - %s[w3i])'):format(i, j_player_control[i], w3i_player_control[i]))
					fail = true
					enable = false
				end

				if j_player_team[i] ~= w3i_player_team[i] and j_player_control[i] then
					print(('[����]: ��Ҷ��鲻ƥ��(���%s:%s[j] - %s[w3i])'):format(i, j_player_team[i], w3i_player_team[i]))
					fail = true
					enable = false
				end
			end

			if enable then
				print('[ͨ��]: ������������ƥ��')
			end

	print('')
	--һЩ���ݼ��
	local ver_124		= j:match('hashtable')
	local ver_120		= j:match('return h%c+return 0')
	local has_record	= j:match('11SAV@')

	if ver_124 then
		print('[ע��]: ��ͼ�汾Ϊ1.24')
	end
	if ver_120 then
		print('[ע��]: ��ͼ�汾Ϊ1.20')
	end
	if has_record then
		print('[ע��]: ��ͼ���»���')
	end

	print('')
	
	--���
	if fail then
		print('=================================================')
		print('[����]: ��ͼ�������޷��ϴ�,��ʱ ' .. os.clock() .. ' ��')
		print('=================================================')
	else
		print('[ͨ��]: ��ͼ������,��ʱ ' .. os.clock() .. ' ��')
	end
	
end

if main() then
end