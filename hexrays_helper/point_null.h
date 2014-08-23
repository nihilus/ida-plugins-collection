#pragma once;

// 执行转换
void safe_convert(cfunc_t *);

// 设置
void point_null_run();

// 隐藏光标所有行的表达式
bool idaapi hide_this_line(void *ud);

// 当前行是否可以隐藏
bool is_current_line_can_hide(vdui_t &vu);

// 自动隐藏 var1 = var1;形式的赋值
void hide_if_asg_equal_var(cfunc_t *cfunc);