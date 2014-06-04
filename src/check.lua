local function main()
	
	--检查参数 arg[1]为地图, arg[2]为本地路径
	if (not arg) or (#arg < 2) then
		print('[错误]: 请将地图拖动到check.bat上进行检验')
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

	--校验文件名
		--检查文件名长度
		if #map_name > 27 then
			print('[错误]: 文件名过长,不能大于27个字符: ' .. #map_name)
			return
		else
			print('[通过]: 文件名长度为: ' .. #map_name)
		end

		--检查是否包含非法字符
			local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._0123456789()'
			--建立反向
			local t = {}
			for i = 1, #chars do
				t[chars:sub(i, i)] = true
			end

			for i = 1, #map_name do
				if not t[map_name:sub(i, i)] then
					print('[错误]: 文件名包含非法字符: ' .. map_name:sub(i, i))
					return
				end
			end
			print('[通过]: 文件名可以使用')

	--打开地图
	local inmap = mpq_open(input_map)
	if inmap then
		print('[成功]: 打开 ' .. input_map:string())
	else
		print('[错误]: 打开 ' .. input_map:string() .. ' ,加密了字头?')
		return
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
		return
	end
	if f_w3i then
		w3i = f_w3i:read('*a')
		f_w3i:close()
		print('[成功]: 打开w3i文件')
	else
		print('[错误]: 没有找到w3i文件')
		return
	end

	--检查起来
		--检查注入脚本式作弊
			local mod = false
			--检查修改痕迹(通过listfile)
				local f_listfile = io.open((test_dir / '(listfile)'):string(), 'r')
				if f_listfile then
					local listfile = f_listfile:read('*a')
					f_listfile:close()
					if listfile:match('war3map.j') then
						print('[警告]: 发现修改痕迹,将进行进一步检查')
						mod = true
					end
				end

			--检查修改痕迹(通过特征码)
				local chars = {'\t', '    ', 'hke_', 'efl_', 'feiba', 'WCDTOF'}
				for _, char in ipairs(chars) do
					if j:match(char) then
						print('[警告]: 发现可疑代码,将进行进一步检查')
						mod = true
						break
					end
				end

			--进行进一步检查
			if mod then
				local ss = {} --存放可疑代码
				for line in io.lines((test_dir / 'war3map.j'):string()) do
					for _, char in ipairs(chars) do
						if line:match(char) then
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

				local cheats = setmetatable({}, {__index = function() return 0 end})
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
					print(('[错误]: 发现可疑的敏感代码\n\t检查行数: %d\n\t%s\n\t总数: %s'):format(#ss, table.concat(cheat_result, '\n\t'), cheat_count))
					return
				else
					print('[通过]: 未发现可疑的敏感代码')
				end
			end

		--检查InitCustomPlayerSlots,InitCustomTeams,InitAllyPriorities这3个函数是否被混淆
			--找到指定函数域
			local f_config = j:match("function config takes nothing returns nothing(.-)endfunction")
			--先检查是否有函数
			if (f_config:find('InitCustomPlayerSlots') or f_config:find('SetPlayerRacePreference'))
			and (f_config:find('InitCustomTeams') or f_config:find('SetPlayerTeam'))
			and (f_config:find('InitAllyPriorities') or f_config:find('SetStartLocPrioCount')) then
				print('[通过]: 在config函数中找到了指定函数')
			else
				print('[错误]: config函数被混淆')
				return
			end

		--检查w3i文件与j文件的队伍设置是否匹配
			

	--完成
	print('[通过]: 用时 ' .. os.clock() .. ' 秒')

	return true
	
end

if not main() then
	os.execute('@pause')
end