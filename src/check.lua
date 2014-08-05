local function main()
	
	--检查参数 arg[1]为地图, arg[2]为本地路径
	if (not arg) or (#arg < 2) then
		print('[错误]: 请将地图拖动到check.bat上进行检验')
		return
	end
	
	local input_map  = arg[1]
	local root_dir   = arg[2]
	
	--添加require搜寻路径
	package.path = package.path .. ';' .. root_dir .. 'src\\?.lua'
	package.cpath = package.cpath .. ';' .. root_dir .. 'build\\?.dll'
	require 'luabind'
	require 'filesystem'
	require 'utility'

	--保存路径
	local input_map    = fs.path(input_map)
	local root_dir     = fs.path(root_dir)

	--地图名
	local map_name = input_map:filename():string():sub(1, -5)
	
	local test_dir     = root_dir / 'test'
	local log_dir      = root_dir / 'log' / os.date('%Y.%m.%d')
	local map_log_dir  = log_dir / ('[' .. os.date('%H.%M.%S') .. ']' .. map_name .. '.txt')

	fs.remove_all(test_dir)
	fs.create_directories(test_dir)

	fs.create_directories(log_dir)

	--加载log
	local f_log = io.open(map_log_dir:string(), 'w')
	
	local oldprint = print
	
	function print(...)
		f_log:write(('[%.3f]%s\n'):format(os.clock(), table.concat({...}, '%t')))
		return oldprint(...)
	end
	
	print('[地图]: ' .. map_name)

	local fail
	
	--校验文件名
		--检查文件名长度
		local enable = true
		if #map_name > 27 then
			print('[错误]: 文件名过长,不能大于27个字符: ' .. #map_name)
			fail = true
		else
			print('[通过]: 文件名长度为: ' .. #map_name)
		end

		--检查是否包含非法字符
			local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._0123456789() '
			--建立反向
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
				print('[错误]: 文件名包含非法字符: ' .. table.concat(ws))
				fail = true
				enable = false
			end
			
			if map_name:find('  ') then
				print('[错误]: 文件名不能包含2个连续的空格')
				fail = true
				enable = false
			end

			if map_name:find('%D%.') or map_name:find('%.%D') then
				print('[错误]: 小数点前后必须是数字')
				fail = true
				enable = false
			end
			
			if enable then
				print('[通过]: 文件名可以使用')
			end

	--去掉文件的只读属性
	if 0 == bit32.band(input_map:permissions(nil), 128) then		
		input_map:permissions(bit32.bor(0x1000, 128))
	end

	--打开地图
	local inmap = mpq_open(input_map)
	if inmap then
		print('[成功]: 打开 ' .. input_map:string())
	else
		print('[错误]: 打开 ' .. input_map:string() .. ' ,文件被占用或加密了字头?')
		return true
	end
	
	--需要导出的文件
	local list_file = {
		{'(listfile)', '(listfile)'},
		{'war3map.w3i', 'war3map.w3i'},
		{'scripts\\war3map.j', 'war3map.j'},
		{'war3map.j', 'war3map.j'},
	}

	--导出这些文件
	for _, t in ipairs(list_file) do
		local mpq_name, file_name = t[1], t[2]
		local file_dir = test_dir / file_name
		if inmap:extract(mpq_name, file_dir) then
			print('[成功]: 导出 ' .. mpq_name)
		else
			print('[失败]: 导出 ' .. mpq_name)
		end
	end

	--关闭掉地图
	inmap:close()

	--读取j文件和w3i文件
	local f_j = io.open((test_dir / 'war3map.j'):string(), 'r')
	local f_w3i = io.open((test_dir / 'war3map.w3i'):string(), 'rb')
	local j, w3i
	if f_j then
		j = f_j:read('*a')
		f_j:close()
		print('[成功]: 打开j文件')
	else
		print('[错误]: 没有找到j文件')
		return true
	end
	if f_w3i then
		w3i = f_w3i:read('*a')
		f_w3i:close()
		print('[成功]: 打开w3i文件')
	else
		print('[错误]: 没有找到w3i文件')
		return true
	end

	--检查起来
		--检查注入脚本式作弊
			local mod = false
			local ss = {} --存放可疑代码
			--检查修改痕迹(通过listfile)
				local f_listfile = io.open((test_dir / '(listfile)'):string(), 'r')
				if f_listfile then
					local listfile = f_listfile:read('*a')
					f_listfile:close()
					if listfile:match('war3map.j') then
						print('[警告]: 发现修改痕迹,将进行进一步检查')
						mod = true
					end
					listfile = listfile:lower()
					if listfile:match('loading') or listfile:match('screen') then
						print('=================================================')
						print('[警告]: 可能替换了载入图')
						print('=================================================')
					end
				end

			--检查修改痕迹(通过InitTrig函数顺序)
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
					print('[警告]: 发现可疑函数,将进行进一步检查')
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
								print(('[%s]: %s\n'):format('注入', line))
								table.insert(ss, line)
							end
						end
					end
				end
				
				
			--检查修改痕迹(通过main函数底部是否有代码判定)
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
								print(('[%s]: %s\n'):format('注入', line))
								table.insert(ss, line)
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

			--检查修改痕迹(通过特征码)
				local chars = {'\t', '    ', 'hke_', 'efl_', '_feiba', 'WCDTOF', 'ou99_', '55you'}

			--动态添加特征码
				local v_name = j:match('string%s+(%a+)%C-Hke')
				if v_name then
					print('[警告]: 发现HKE关键字')
					table.insert(chars, v_name)
				end
				
				for _, char in ipairs(chars) do
					if j:match(char) then
						print('[警告]: 发现可疑代码,将进行进一步检查')
						mod = true
						break
					end
				end
			
			--进行进一步检查
			if mod then
				local lines = {} --行数
				local count = 0 --存放'\t'和'    '的计数
				for line in io.lines((test_dir / 'war3map.j'):string()) do
					table.insert(lines, line)
					if line:match('\t') or line:match('    ') or line:match('//') then
						count = count + 1
					end
				end

				if count / #lines > 0.25 then
					print('[注意]: 地图脚本可能没有进行优化: ' .. (count / #lines))
					table.remove(chars, 1)
					table.remove(chars, 1)
				elseif count / #lines > 0.05 then
					print('[注意]: 发现大量制表符与空格,请手动检查地图是否进行过优化: ' .. (count / #lines))
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
					{'CreateTrigger', '创建触发器'},
					{'CreateTimer', '创建计时器'},
					{'TimerStart', '启动计时器'},
					{'StartTimer', '启动计时器'},
					{'AddItem', '添加物品'},
					{'SetItem', '设置物品'},
					{'EventPlayerChatString', '聊天信息'},
					{'FogMaskEnable', '清除迷雾'},
					{'FogEnable', '清除迷雾'},
					{'UnitResetCooldown', '重置冷却'},
					{'SetHero', '设置英雄'},
					{'SetUnit', '设置单位'},
					{'SetPlayer', '设置玩家'},
					{'PlayerState', '玩家属性'},
					{'UnitAddAbility', '添加技能'},
					{'Dialog', '对话框'},
					{'TriggerRegister', '注册触发器'},
					{'TriggerAdd', '注册触发器'},
					{'_GOLD', '玩家金钱'},
					{'_LUMBER', '玩家木材'},
					{'_LIFE', '单位生命'},
					{'_MANA', '单位法力'},
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
					print(('[错误]: 发现可疑的敏感代码,地图可能包含作弊代码\n\t检查行数: %d\n\t%s\n\t总数: %s'):format(#ss, table.concat(cheat_result, '\n\t'), cheat_count))
					fail = true
				else
					print('[通过]: 未发现可疑的敏感代码')
				end
			end

		--检查InitCustomPlayerSlots,InitCustomTeams,InitAllyPriorities这3个函数是否被混淆
			--找到指定函数域
			local f_config = j:match("function%s+config%s+takes%s+nothing%s+returns%s+nothing(.-)endfunction")
			--先检查是否有函数
			if (f_config:match('SetPlayerRacePreference') or j:match('%sInitCustomPlayerSlots%s') or not j:match('SetPlayerRacePreference'))
			and (f_config:match('PLAYER_STATE_ALLIED_VICTORY') or j:match('%sInitCustomTeams%s') or not j:match('PLAYER_STATE_ALLIED_VICTORY'))
			and (f_config:match('SetStartLocPrioCount') or j:match('%sInitAllyPriorities%s') or not j:match('SetStartLocPrioCount')) then
				print('[通过]: 找到了指定config函数')
			else
				print('[错误]: config函数被混淆')
				fail = true
			end

		--检查w3i文件与j文件的队伍设置是否匹配
			--记录j文件中的队伍设置
				local j_players, j_teams, j_player_control, j_player_team, f_now = 0, 0, {}, table.new(0)
				do
					--重载tonumber,为了那该死的十六进制
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

				print('[成功]: 分析j文件中的玩家设置')

			--记录w3i文件中的队伍设置
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
				
				--找到玩家设置的偏移
				local x, y, byte = w3i:find(string.char(0xff) .. '(%Z)%z%z%z.%z%z%z.%z%z%z.%z%z%z.%z%z%z%Z-%z')
				w3i_players = tonumber(byte:byte())
				
				--从这里开始是玩家数据
				w3i_now = w3i:sub(x + 5)

				local controls = {
					'MAP_CONTROL_USER',
					'MAP_CONTROL_COMPUTER',
					'MAP_CONTROL_NEUTRAL',
					'MAP_CONTROL_RESCUABLE',
				}
				--匹配玩家控制者
				local x = -1
				for i, t, name in w3i_now:gmatch('(.)%z%z%z(.)%z%z%z.%z%z%z.%z%z%z(%Z-)%z................') do
					i, t = i:byte(), t:byte()
					if i > x then
						w3i_player_control[i] = controls[t]
						x = i
					end
				end

				--匹配队伍信息
					x = 0
					--先处理第一个队伍信息,比较特殊
					local _, y, teams, w1, w2, teamname = w3i_now:find('(.)%z%z%z.%z%z%z(.)(.)' .. string.char(0xff, 0xff) .. '(%Z-)%z')
					w3i_teams = teams:byte()
					local players = (w1:byte() + w2:byte() * 0x100) - 0xf000
					w3i_addTeam(players, x)
					--开始处理后面的队伍,如果有的话
					if w3i_teams > 1 then
						--从这里开始是后面的队伍数据
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

					print('[成功]: 分析w3i文件中的玩家设置')

			--开始对比j与w3i
			print('[成功]: 开始对比j文件与w3i文件中的玩家设置')
			local enable = true
			if j_players ~= w3i_players then
				print(('[错误]: 玩家数量不匹配(%s[j] - %s[w3i])'):format(j_players, w3i_players))
				fail = true
				enable = false
			end

			--[[
			---不检查teams,因为config函数中的SetTeams不准确
			if j_teams ~= w3i_teams then
				print(('[错误]: 队伍数量不匹配(%s[j] - %s[w3i])'):format(j_teams, w3i_teams))
				fail = true
			end
			--]]

			for i = 0, 11 do
				if j_player_control[i] ~= w3i_player_control[i] then
					print(('[错误]: 玩家控制者不匹配(玩家%s:%s[j] - %s[w3i])'):format(i, j_player_control[i], w3i_player_control[i]))
					fail = true
					enable = false
				end

				if j_player_team[i] ~= w3i_player_team[i] and j_player_control[i] then
					print(('[错误]: 玩家队伍不匹配(玩家%s:%s[j] - %s[w3i])'):format(i, j_player_team[i], w3i_player_team[i]))
					fail = true
					enable = false
				end
			end

			if enable then
				print('[通过]: 玩家与队伍设置匹配')
			end

	--完成
	if fail then
		print('=================================================')
		print('[错误]: 地图有问题无法上传,用时 ' .. os.clock() .. ' 秒')
		print('=================================================')
	else
		print('[通过]: 地图检查完毕,用时 ' .. os.clock() .. ' 秒')
	end
	
end

if main() then
end