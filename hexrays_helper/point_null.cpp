//////////////////////////////////////////////////////////////////////////
// 
#include <hexrays.hpp>

#include "map_var.h"

static const char nodename[] = "$ hexrays NULLs";
static const char null_type[] = "MACRO_NULL";
static const type_t voidptr[] = { BT_PTR, BT_VOID, 0 };
//--------------------------------------------------------------------------
// Is the plugin enabled?
// The user can disable it. The plugin will save the on/off switch in the
// current database.
static bool is_enabled(void)
{
  netnode n(nodename); // use a netnode to save the state
  return n.altval(0) == 0; // if the long value is positive, then disabled
}

//--------------------------------------------------------------------------
// If the expression is zero, convert it to NULL
static void make_null_if_zero(cexpr_t *e)
{
  if ( e->is_zero_const() && !e->type.is_ptr() )
  { // this is plain zero, convert it
    number_format_t &nf = e->n->nf;
    nf.flags = enumflag();
    nf.serial = 0;
    nf.type_name = null_type;
    e->type = voidptr;
  }
}

//--------------------------------------------------------------------------
// Convert zeroes of the ctree to NULLs
static void convert_zeroes(cfunc_t *cfunc)
{
  // To represent NULLs, we will use the MACRO_NULL enumeration
  // Normally it is present in the loaded tils but let's verify it
  if ( !get_named_type(idati, null_type, NTF_TYPE) )
  {
    msg("%s type is missing, can not convert zeroes to NULLs\n", null_type);
    return;
  }

  // We derive a helper class from ctree_visitor_t
  // The ctree_visitor_t is a base class to derive
  // ctree walker classes.
  // You have to redefine some virtual functions
  // to do the real job. Here we redefine visit_expr() since we want
  // to examine and modify expressions.
  struct zero_converter_t : public ctree_visitor_t
  {
    zero_converter_t(void) : ctree_visitor_t(CV_FAST) {}
    int idaapi visit_expr(cexpr_t *e)
    {
      // verify if the current expression has pointer expressions
      // we handle the following patterns:
      //  A. ptr = 0;
      //  B. func(0); where argument is a pointer
      //  C. ptr op 0 where op is a comparison
      switch ( e->op )
      {
        case cot_asg:   // A
          if ( e->x->type.is_ptr() )
            make_null_if_zero(e->y);
          break;

        case cot_call:  // B
          {
            carglist_t &args = *e->a;
            for ( int i=0; i < args.size(); i++ ) // check all arguments
            {
              carg_t &a = args[i];
              if ( a.formal_type.is_ptr_or_array() )
                make_null_if_zero(&a);
            }
          }
          break;

        case cot_eq:    // C
        case cot_ne:
        case cot_sge:
        case cot_uge:
        case cot_sle:
        case cot_ule:
        case cot_sgt:
        case cot_ugt:
        case cot_slt:
        case cot_ult:
          // check both sides for zeroes
          if ( e->y->type.is_ptr() )
            make_null_if_zero(e->x);
          if ( e->x->type.is_ptr() )
            make_null_if_zero(e->y);
          break;

      }
      return 0; // continue walking the tree
    }
  };
  zero_converter_t zc;
  // walk the whole function body
  zc.apply_to(&cfunc->body, NULL);
}

void safe_convert(cfunc_t *cfunc)
{
	if (is_enabled()) 
	{
		convert_zeroes(cfunc);
	}	
}

//--------------------------------------------------------------------------
void point_null_run()
{
  // since all real work is done in the callbacks, use the main plugin entry
  // to turn it on and off.
  // display a message explaining the purpose of the plugin:
  int code = askbuttons_c(
       "~E~nable",
       "~D~isable",
       "~C~lose",
       -1,
       "AUTOHIDE NONE\n"
       "Sample plugin for Hex-Rays decompiler.\n"
       "\n" 
       "This plugin is fully automatic.\n"
       "It detects zeroes in pointer contexts and converts them into NULLs.\n"
       "\n"
       "The current state of the plugin is: %s\n",
       is_enabled() ? "ENABLED" : "DISABLED");
  switch ( code )
  {
    case -1:    // close
      break;
    case 0:     // disable
    case 1:     // enable
      netnode n;
      n.create(nodename);
      n.altset(0, code == 0);
     
      info("The %s plugin has been %s.", PLUGIN.wanted_name, code ? "ENABLED" : "DISABLED");
      break;
  }
}
//////////////////////////////////////////////////////////////////////////
/*!
  \brief: 当前行是否可以隐藏
  \return: bool
  \param vu
*/
bool is_current_line_can_hide(vdui_t &vu)
{
	if (vu.item.citype == VDI_EXPR && vu.item.e->op == cit_expr) 
	{
		return true;
	}
	return false;
}

/*!
  \brief: 当选择"隐藏当前行"菜单项时会进来
  \return: bool
  \param ud
*/
bool idaapi hide_this_line(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
	vu.item.i->cleanup();
	vu.refresh_ctext();
	return true;
}
//////////////////////////////////////////////////////////////////////////
/*!
  \brief: 隐藏 var1 = var1形式的赋值表达式, 含强转的不行
  \return: void
  \param cfunc
*/
void hide_if_asg_equal_var(cfunc_t *cfunc)
{
	// 迭代器中干活
	struct if_inverter_t : public ctree_visitor_t
	{
		if_inverter_t() : ctree_visitor_t(CV_PARENTS){}
		/*!
		  \brief: 隐藏当前的表达式
		  \return: void
		  \param e
		*/
		void hide_this_expr(cexpr_t* e)
		{
			cexpr_t *pParent = NULL;
			int n = parents.size();
			for (int i = 1; i < n; ++i) 
			{
				pParent = (cexpr_t *)parents.at(n-i);
				// 取到表达式隐藏
				if (pParent->ea != 0xffffffff && pParent->op == cit_expr) 
				{
					cinsn_t* i = (cinsn_t*)pParent;
					i->op = cit_empty;
					break;
				}
			} // end for with i < n
		}

		// 处理赋值表达式,如果X Y是同一个变量,就取到父达式隐藏掉
		int idaapi visit_expr(cexpr_t *e)
		{
			if (e->op == cot_asg) 
			{
				if (e->x->op == cot_var && e->y->op == cot_var) 
				{
					if (e->x->v.idx == e->y->v.idx) 
					{
						hide_this_expr(e);
					}
				}
			}
			return 0; // continue enumeration
		}
	};
	// 处理有前科的,提高效率
	if (is_func_in_list(cfunc->entry_ea)) 
	{
		if_inverter_t ifi;
		ifi.apply_to(&cfunc->body, NULL); 
	}
}