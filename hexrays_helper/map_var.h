//////////////////////////////////////////////////////////////////////////
#pragma once;

/// 处理变量映射
bool idaapi map_var_to(void *ud);

/// 处理变量反映射
bool idaapi ummap_var_from(void *ud);

/// 获取初始化信息
void init_map_var_if();

/// 修改变量名
void change_var_name(cfunc_t *cfunc);

// 判断当前光标处变量是否能反映射
bool is_var_can_unmap(vdui_t &vu);

// 返回当前要反编译的函数是否曾被我们的插件处理过
bool is_func_in_list(ea_t ea);