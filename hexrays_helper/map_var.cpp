//////////////////////////////////////////////////////////////////////////
// 
#include <hexrays.hpp>

/// 存储变量映射信息的结构
static const char nodename[] = "$ hexrays map_var";
static netnode var_node;
/*! \brief 用于变量替换的结构*/
typedef struct var_info{
	int new_name_index; ///< 新索引
	int old_name_index; ///< 旧索引	
	ea_t func_addr;		///< 函数地址
	bool operator== (const var_info& vi) const
	{
		if (old_name_index == vi.old_name_index &&
			new_name_index == vi.new_name_index &&
			func_addr      == vi.func_addr) 
		{
			return true;
		}
		return false;
	}
}var_info;
static qvector<var_info> var_map_info; ///< 新旧变量的索引对

static const char res_nodename[] = "$ hexrays res_var";
static netnode res_node;
/*! \brief 还原变量所要用到的结构 保存了旧变量父表达式的类型与父表达式的地址*/
typedef struct restore_info{
	int		old_idx;///< 索引
	ctype_t	op;		///< 父表达式的类型
	ea_t	defea;	///< 父表达式的地址
	ea_t	func_addr;		///< 函数地址
	bool operator== (const restore_info& vi) const
	{
		if (old_idx == vi.old_idx && op == vi.op && defea == vi.defea && func_addr == vi.func_addr) 
		{
			return true;
		}
		return false;
	}
}restore_info;
static qvector<restore_info> res_map_info; ///< 旧变量的使用信息,用于还原

// 变量映射选择框的列宽
static const int widths[] = {10, 15};
// 变量映射选择框的标题
static const char *header[] ={"Var type", "var name"};
CASSERT(qnumber(widths) == qnumber(header));

//////////////////////////////////////////////////////////////////////////
// 变量映射
//////////////////////////////////////////////////////////////////////////
/*!
  \brief: 初始化时从数据库中读取信息
  \return: void
*/
void init_map_var_if()
{
	if (!var_node.create(nodename)) 
	{
		// 如果已存在则失败,读取即可
		size_t n = var_node.altval(-1);
		if ( n > 0 )
		{ // 读取信息
			var_map_info.resize(n);
			n *= sizeof(var_info);
			var_node.getblob(&var_map_info[0], &n, 0, 'S');
		}
	}

	if (!res_node.create(res_nodename)) 
	{
		// 如果已存在则失败,读取即可
		size_t n = res_node.altval(-1);
		if ( n > 0 )
		{ // 读取信息
			res_map_info.resize(n);
			n *= sizeof(restore_info);
			res_node.getblob(&res_map_info[0], &n, 0, 'J');
		}
	}
	
	return;
}

/*!
  \brief: 修改变量名
  \return: void
  \param cfunc
*/
void change_var_name(cfunc_t *cfunc)
{
	// 用迭代器类修改所有变量
	struct if_inverter_t : public ctree_visitor_t
	{
		int old_idx;
		int new_idx;
		ea_t func_addr;
		if_inverter_t(int idx_o, int idx_n, ea_t addr) : 
		ctree_visitor_t(CV_PARENTS), 
			old_idx(idx_o),
			new_idx(idx_n),
			func_addr(addr){}
		/*!
		  \brief: 保存足够信息为了变量还原时使用
		  \return: void
		  \param e
		*/
		void save_in_info(cexpr_t* e)
		{
			cexpr_t *pParent = NULL;
			int n = parents.size();
			for (int i = 1; i < n; ++i) 
			{
				pParent = (cexpr_t *)parents.at(n-i);
				if (pParent->ea != 0xffffffff) // 只要地址不为-1就干活,否则一直向上取
				{
					/// 保存信息
					restore_info info = {old_idx, pParent->op, pParent->ea, func_addr};
					if (!res_map_info.has(info))  // 如果未找到则添加
					{
						res_map_info.push_back(info);
						// 存储到数据库
						res_node.setblob(&res_map_info[0], res_map_info.size()*sizeof(restore_info), 0, 'J');
						res_node.altset(-1, res_map_info.size());
					}
					break;
				}
			} // end for with i < n
		}

		/*!
		  \brief: 处理所有局部变量,替换索引
		  \return: int idaapi
		  \param e
		*/
		int idaapi visit_expr(cexpr_t *e)
		{
			if (e->op == cot_var)
			{
				if (e->v.idx == old_idx) 
				{
					save_in_info(e);
					e->v.idx = new_idx;
				}
			}
			return 0; // continue enumeration
		}
	};

	lvars_t &lvars = *cfunc->get_lvars(); // 所有变量
	// 遍历所有要修改的变量,修改之
	qvector<var_info>::iterator it = var_map_info.begin();
	for (; it != var_map_info.end(); ++it) 
	{
		if ((*it).func_addr == cfunc->entry_ea) 
		{
			if_inverter_t ifi((*it).old_name_index, (*it).new_name_index, cfunc->entry_ea);
			ifi.apply_to(&cfunc->body, NULL); 
			// 置成未使用
			lvars[(*it).old_name_index].clear_used();
		}
	}
	return;
}

/*!
  \brief: 返回变量映射选择框的行数
  \return: uint32 行数
  \param obj
*/
static uint32 idaapi map_var_sizer(void *obj)
{
	netnode *node = (netnode *)obj;
	return (uint32)node->altval(-1); // 总行数
}

/*!
  \brief: 填充每行数据
  \return: void
  \param obj
  \param n 当前行
  \param arrptr 数据
*/
static void idaapi map_var_desc(void *obj,uint32 n,char * const *arrptr)
{
	if ( n == 0 ) // 标题
	{
		for ( int i=0; i < qnumber(header); i++ )
			qstrncpy(arrptr[i], header[i], MAXSTR);
		return;
	}
	netnode *node = (netnode *)obj;
	lvar_t& lavr = *(lvar_t*)node->altval(n-1);
	
	if (!lavr._type.empty())
	{
		print_type_to_one_line(arrptr[0], MAXSTR, idati, lavr._type.c_str());
	}
	qsnprintf(arrptr[1], MAXSTR, "%s", lavr.name.c_str());
}

/*!
  \brief: 当选择"映射变量"菜单项时会进来
  \return: bool 
  \param ud
*/
bool idaapi map_var_to(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
	lvars_t &lvars = *vu.cfunc->get_lvars();
	// 
	netnode* node = new netnode;
	node->create();
	
	// 2: 统计所有使用中的变量个数
	int total_count = 0;
	lvars_t::iterator it = lvars.begin();
	for (int i = 0; it != lvars.end(); ++it, ++i) 
	{
		// 选中的变量忽略
		if (i == vu.item.e->v.idx) 
		{
			continue;
		}
		
		if ((*it).used()) 
		{
			node->altset(total_count, (nodeidx_t)&(*it));
			++total_count;
		}
	}
	/// 总共可显示的数量放到-1索引处,填充数据时用
	node->altset(-1, total_count);
	char szTitle[MAXSTR] = { 0 };
	qsnprintf(szTitle, MAXSTR, "map %s to", lvars[vu.item.e->v.idx].name.c_str());
	int choose_code = choose2(CH_MODAL,                    // modal window
		-1, -1, -1, -1,       // position is determined by Windows
		node,                 // 数据
		qnumber(header),      // number of columns
		widths,               // widths of columns
		map_var_sizer,                // function that returns number of lines
		map_var_desc,                 // function that generates a line
		szTitle,         // window title
		-1,                   // use the default icon for the window
		0,                    // position the cursor on the first line
		NULL,                 // "kill" callback
		NULL,                 // "new" callback
		NULL,                 // "update" callback
		NULL,                 // "edit" callback
		NULL,                 // function to call when the user pressed Enter
		NULL,                 // function to call when the window is closed
		NULL,                 // use default popup menu items
		NULL);                // use the same icon for all lines
	if (choose_code <= 0) // 木有选择
	{
		node->kill();
		delete node;
		return true;
	}
	// 由选中的索引转成变量索引
	lvar_t& choose_var = *(lvar_t*)node->altval(choose_code-1);
	
	int idx = 0;
	for (it = lvars.begin(); it != lvars.end(); ++it, ++idx) 
	{
		if (choose_var == (*it)) 
		{
			break;
		}
	}
	// 保存数据
	var_info info = {idx, vu.item.e->v.idx, vu.cfunc->entry_ea};
	var_map_info.push_back(info);
	// 修改名字
	change_var_name(vu.cfunc);
	// 存储到数据库
	var_node.setblob(&var_map_info[0], var_map_info.size()*sizeof(var_info), 0, 'S');
	var_node.altset(-1, var_map_info.size());
	
	// 刷新重新生成ctree结构,
	vu.refresh_view(false);
	node->kill();
	delete node;
	return true;
}
//////////////////////////////////////////////////////////////////////////
// 变量反映射
//////////////////////////////////////////////////////////////////////////
/*!
  \brief: 判断当前光标处变量是否能反映射
  \return: bool 行不行?
  \param vu
*/
bool is_var_can_unmap(vdui_t &vu)
{
	qvector<var_info>::iterator it = var_map_info.begin();
	for (; it != var_map_info.end(); ++it) 
	{
		if ((*it).new_name_index == vu.item.e->v.idx && (*it).func_addr == vu.cfunc->entry_ea) 
		{
			return true;
		}
	}
	return false;
}

/*!
  \brief: 返回当前要反编译的函数是否曾被我们的插件处理过
  \return: bool
  \param ea
*/
bool is_func_in_list(ea_t ea)
{
	qvector<var_info>::iterator it = var_map_info.begin();
	for (; it != var_map_info.end(); ++it) 
	{
		if ((*it).func_addr == ea) 
		{
			return true;
		}
	}
	return false;
}

/*!
  \brief: 还原变量名
  \return: void
  \param cfunc
  \param info
*/
void restore_var_name(cfunc_t * cfunc, var_info &info)
{
	/*! \brief 用迭代器类修改所有变量*/
	struct if_inverter_t : public ctree_visitor_t
	{
		cfunc_t* m_func;
		qstring disp_name;
		int new_idx;
		if_inverter_t(cfunc_t* func, qstring name, int idx_n) : 
		ctree_visitor_t(CV_PARENTS), 
			m_func(func), 
			disp_name(name),
			new_idx(idx_n){}
		/*!
		  \brief: 要还原的操作类型与表达式址是否相同
		  \return: bool
		  \param e
		*/
		bool is_restore_info_equal(cexpr_t* e)
		{
			cexpr_t *pParent = NULL;
			int n = parents.size();
			// 根据当前表达式找到第一个可用的父表达式
			for (int i = 1; i < n; ++i) 
			{
				pParent = (cexpr_t *)parents.at(n-i);
				if (pParent->ea != 0xffffffff) // 只要地址不为-1就一直向上取
				{
					break;
				}
			} // end for with i < n
			if (pParent == NULL) 
			{
				return false;
			}
			
			// 根据已存储的信息进行匹配,找到则返回true
			qvector<restore_info>::iterator it = res_map_info.begin();
			for (; it != res_map_info.end(); ++it) 
			{
				restore_info& info = (*it);
				if (info.func_addr == m_func->entry_ea && 
					info.old_idx == new_idx && 
					info.op == pParent->op && 
					info.defea == pParent->ea) 
				{
					// 从数据库中删除相应数据
					res_map_info.del(info);
					res_node.setblob(&res_map_info[0], res_map_info.size()*sizeof(restore_info), 0, 'J');
					res_node.altset(-1, res_map_info.size());
					return true;
				}
			}
			return false;
		}
		int idaapi visit_expr(cexpr_t *e)
		{
			if (e->op == cot_var)
			{
				lvar_t &var = m_func->get_lvars()->at(e->v.idx);
				if (var.name == disp_name && is_restore_info_equal(e)) 
				{
					e->v.idx = new_idx;
				}
			}
			return 0; // continue enumeration
		}
	};

	// 还原变量名
	qstring name = cfunc->get_lvars()->at(info.new_name_index).name;
	if_inverter_t ifi(cfunc, name, info.old_name_index);
	ifi.apply_to(&cfunc->body, NULL); 
	return;
}

/*!
  \brief: 变量的反映射
  \return: bool 
  \param ud
*/
bool idaapi ummap_var_from(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
	// 新建数据对象,存放显示数据
	netnode* node = new netnode;
	node->create();

	// 遍历数据库,将所有映射到此变量的变量都取出
	qvector<int> vec_old_idx;
	int total_count = 0;
	lvars_t &lvars = *vu.cfunc->get_lvars();
	qvector<var_info>::iterator it = var_map_info.begin();
	for (; it != var_map_info.end(); ++it) 
	{
		if ((*it).new_name_index == vu.item.e->v.idx && (*it).func_addr == vu.cfunc->entry_ea) 
		{
			node->altset(total_count, (nodeidx_t)&lvars[(*it).old_name_index]);
			vec_old_idx.push_back((*it).old_name_index);
			++total_count;
		}
	}
	node->altset(-1, total_count); // 总数
	char szTitle[MAXSTR] = { 0 };
	qsnprintf(szTitle, MAXSTR, "unmap var from %s", lvars[vu.item.e->v.idx].name.c_str());
	int choose_code = choose2(
		CH_MODAL, 
		-1, -1, -1, -1, 
		node, 
		qnumber(header), 
		widths, 
		map_var_sizer, 
		map_var_desc, 
		szTitle, 
		-1, 0, 
		NULL, NULL, NULL, NULL, 
		NULL, NULL, NULL, NULL);
	if (choose_code <= 0) // 木有选择
	{
		node->kill();
		delete node;
		return true;
	}
	int index = vec_old_idx.at(choose_code - 1);
	qvector<var_info>::iterator ittmp = var_map_info.begin();
	for (; ittmp != var_map_info.end(); ++ittmp) 
	{
		if ((*ittmp).old_name_index == index && (*ittmp).func_addr == vu.cfunc->entry_ea) 
		{
			break;
		}
	}
	// 从数据库中删除该变量的映射数据
	var_map_info.del(*ittmp);
	var_node.setblob(&var_map_info[0], var_map_info.size()*sizeof(var_info), 0, 'S');
	var_node.altset(-1, var_map_info.size());

	// 还原变量名
	lvars[(*ittmp).old_name_index].set_used();
	restore_var_name(vu.cfunc, *ittmp);	
	// 调用重新生成ctree
	vu.refresh_view(false);
	node->kill();
	delete node;
	return true;
}