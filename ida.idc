//
//      This file is automatically executed when IDA is started.
//      You can define your own IDC functions and assign hotkeys to them.
//
//      You may add your frequently used functions here and they will
//      be always available.
///     Add some usefull shortcuts to IDA by HTC - VinCSS (a member of Vingroup)
//

#include <idc.idc>

//-----------------------------------------------------------------------
// A singleton class for managing breakpoints
class BreakpointManager
{
    // Return the breakpoint quantity
    Count()
    {
        return get_bpt_qty();
    }

    // Return a breakpoint object
    Get(index)
    {
        auto count = this.Count();
        if (index >= count)
            throw sprintf("Invalid breakpoint index %d (0..%d expected).", index, count);
        return Breakpoint(index);
    }

    // Add a breakpoint
    Add(bpt)
    {
        return bpt._add();
    }

    // Add a breakpoint to group
    AddToGroup(bpt, group_name)
    {
        return bpt._add(group_name);
    }

    // Delete a breakpoint
    Delete(bpt)
    {
        return bpt._delete();
    }

    // Update a breakpoint
    // Note: Location attributes cannot be updated, recreation of the
    //       breakpoint is required
    Update(bpt)
    {
        return bpt._update();
    }

    // Find a breakpoint using its location attributes and
    // returns a new breakpoint object or 0
    Find(bpt)
    {
        return bpt._find();
    }
}

// Breakpoint manager class instance
extern Breakpoints;

//-----------------------------------------------------------------------
// Get signed extended 16-bit value
static SWord(ea)
{
    auto v = get_wide_word(ea);
    if (v & 0x8000)
        v = v | ~0xFFFF;
    return v;
}
//
// HTC - begin
//-----------------------------------------------------------------------
static CreateUnicodeString()
{
    auto ea = get_screen_ea();

    auto w = 0;
    auto endEA = ea;
    while (endEA != BADADDR)
    {
        w = get_wide_word(endEA);
        if (0 == w)
        {
            break;
        }
        else
        {
            endEA = endEA + 2;
        }
    }

    if (endEA > ea)
    {
        del_items(ea, DELIT_SIMPLE, endEA - ea);

        auto old_type = get_inf_attr(INF_STRTYPE);
        set_inf_attr(INF_STRTYPE, STRTYPE_C_16);
        create_strlit(ea);
        set_inf_attr(INF_STRTYPE, old_type);
    }
}
//-----------------------------------------------------------------------
static JumpToPrevLabel()
{
    auto name;
    auto ea = prev_not_tail(get_screen_ea());
    while (BADADDR != ea)
    {
        name = get_name(ea);
        if (strlen(name) > 0)
        {
            break;
        }

        ea = prev_not_tail(ea);
    }

    // Found an ea ?
    if (BADADDR != ea)
    {
        jumpto(ea);
    }
}
//-----------------------------------------------------------------------
static JumpToNextLabel()
{
    auto name;
    auto ea = next_not_tail(get_screen_ea());
    while (BADADDR != ea)
    {
        name = get_name(ea);
        if (strlen(name) > 0)
        {
            break;
        }

        ea = next_not_tail(ea);
    }

    // Found an ea ?
    if (BADADDR != ea)
    {
        jumpto(ea);
    }
}
//-----------------------------------------------------------------------
static JumpToBeginOfFunction()
{
    auto ea;
    ea = get_func_attr(get_screen_ea(), FUNCATTR_START);
    if (BADADDR != ea)
    {
        jumpto(ea);
    }
}
//-----------------------------------------------------------------------
static JumpToEndOfFunction()
{
    auto ea;
    ea = get_func_attr(get_screen_ea(), FUNCATTR_END);
    if (BADADDR != ea)
    {
        ea = prev_not_tail(ea);
        jumpto(ea);
    }
}
//-----------------------------------------------------------------------
static RegisterHotkeys()
{
    msg("\n------------------------------ HTCHotkeys --------------------------------------\n");

    del_idc_hotkey("Shift+U");
    add_idc_hotkey("Shift+U", "CreateUnicodeString");
    msg("Press Shift+U at screen EA to create Unicode string\n");

    del_idc_hotkey("Alt+Shift+Up");
    add_idc_hotkey("Alt+Shift+Up", "JumpToBeginOfFunction");
    msg("Press Alt+Shift+Up at screen EA to jump to begin of current function\n");

    del_idc_hotkey("Alt+Shift+Down");
    add_idc_hotkey("Alt+Shift+Down", "JumpToEndOfFunction");
    msg("Press Alt+Shift+Down at screen EA to jump to end of current function\n");

    del_idc_hotkey("Ctrl+Alt+Up");
    add_idc_hotkey("Ctrl+Alt+Up", "JumpToPrevLabel");
    msg("Press Ctrl+Alt+Up at screen EA to jump to previous label\n");

    del_idc_hotkey("Ctrl+Alt+Down");
    add_idc_hotkey("Ctrl+Alt+Down", "JumpToNextLabel");
    msg("Press Ctrl+Alt+Down at screen EA to jump to next label\n");

    msg("--------------------------------------------------------------------------------\n\n");
}
//  HTC - end
//
//-----------------------------------------------------------------------
static main(void)
{
    //
    //      This function is executed when IDA is started.
    //
    //      Add statements to fine-tune your IDA here.
    //

    // Instantiate the breakpoints singleton object
    Breakpoints = BreakpointManager();

    // uncomment this line to remove full paths in the debugger process options:
    // set_inf_attr(INF_LFLAGS, LFLG_DBG_NOPATH | get_inf_attr(INF_LFLAGS));

    // HTC
    RegisterHotkeys();
}
