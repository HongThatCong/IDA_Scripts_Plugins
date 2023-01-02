//
// This file is automatically executed when IDA is started.
// You can define your own IDC functions and assign hotkeys to them.
//
// You may add your frequently used functions here and they will
// be always available.
//
// You can customize the initial behaviour of IDA without modifying
// this file but by putting your logic in
//  %appdata%/Hex-Rays/IDA Pro/idauser.idc  (Windows)
//  $HOME/.idapro/idauser.idc               (Linux & Mac)
// Define the function called user_main() there and it will be called.
//
#include <idc.idc>
#softinclude <idauser.idc> // please define user_main() in this file.

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
        {
            throw sprintf("Invalid breakpoint index %d (0..%d expected).", index, count);
        }
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
    {
        v = v | ~0xFFFF;
    }
    return v;
}
//
// Appcall functions
//-----------------------------------------------------------------------
extern last_cmd, last_opt;

static Appcall_Here()
{
    auto t, h;

    t = parse_decl("void x(void);", 0);
    h = get_screen_ea;

    last_opt = get_inf_attr(INF_APPCALL_OPTIONS);
    set_inf_attr(INF_APPCALL_OPTIONS, APPCALL_MANUAL);
    dbg_appcall(get_first_seg(), t);
    set_inf_attr(INF_APPCALL_OPTIONS, last_opt);
#ifdef Eip
    Eip = h;
#endif
}

static Appcall_Start()
{
    auto s = ask_str(last_cmd, 0, "Enter Appcall");
    if (s == "")
    {
        return;
    }
    last_cmd = s;
    last_opt = get_inf_attr(INF_APPCALL_OPTIONS);
    set_inf_attr(INF_APPCALL_OPTIONS, APPCALL_MANUAL);
    msg(">%s<", s);
    eval(s);
    set_inf_attr(INF_APPCALL_OPTIONS, last_opt);
}

//
// HTC - begin
//-----------------------------------------------------------------------
static CreateUnicodeString()
{
    auto old_type = 0;

    // Check user selected a range
    auto start_sel = read_selection_start();
    auto end_sel = read_selection_end();
    if ((start_sel != BADADDR) && (end_sel != BADADDR))
    {
        old_type = get_inf_attr(INF_STRTYPE);
        set_inf_attr(INF_STRTYPE, STRTYPE_C_16);
        create_strlit(start_sel, end_sel - start_sel);
        set_inf_attr(INF_STRTYPE, old_type);
    }
    else
    {
        auto w = 0;
        auto ea = get_screen_ea();
        auto endEA = ea;

        // User not selected a range, begin scan 0x00 0x00 byte from current screen ea
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
            del_items(ea, DELIT_DELNAMES, endEA - ea + 2);

            old_type = get_inf_attr(INF_STRTYPE);
            set_inf_attr(INF_STRTYPE, STRTYPE_C_16);
            create_strlit(ea, endEA - ea + 2);
            set_inf_attr(INF_STRTYPE, old_type);
        }
    }
}

//-----------------------------------------------------------------------
static JumpToPrevLabel()
{
    auto f = 0;
    auto ea = prev_not_tail(get_screen_ea());
    while (BADADDR != ea)
    {
        f = get_full_flags(ea);
        if (f & FF_ANYNAME)
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
    else
    {
        msg("Could not find prev label\n");
    }
}

//-----------------------------------------------------------------------
static JumpToNextLabel()
{
    auto f = 0;
    auto ea = next_not_tail(get_screen_ea());
    while (BADADDR != ea)
    {
        f = get_full_flags(ea);
        if (f & FF_ANYNAME)
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
    else
    {
        msg("Could not find next label\n");
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
// bad code to avoid rva offset 32 :(
static NamePointer()
{
    auto ea, f, s_asm, s_name, p_first, p_second;
    auto i, len, ch;

    ea = get_screen_ea();
    f = get_flags(ea);
    if (is_data(f) && is_off0(f) && (is_qword(f) || is_dword(f)))
    {
        s_asm = generate_disasm_line(ea, 0);
        p_first = strstr(s_asm, " offset ");
        if (-1 != p_first)
        {
            s_name = substr(s_asm, p_first + 8, -1);    // 8 = strlen(" offset ")

            // Remove comment trailing
            p_second = strstr(s_name, ";");
            if (-1 != p_second)
            {
                s_name = substr(s_name, 0, p_second);
            }

            // replcae +, :, space... with _ char
            len = strlen(s_name);
            if (len > 0)
            {
                for (i = 0; i < len; ++i)
                {
                    ch = s_name[i];
                    if (("+" == ch) || (":" == ch) || (" " == ch))
                    {
                        s_name[i] = "_";
                    }
                }

                s_name = "p_" + s_name;
                set_name(ea, s_name, SN_CHECK | SN_NOWARN | SN_FORCE);

                return 1;
            }
            else
            {
                msg("0x%X: name is empty\n");
            }
        }
        else
        {
            msg("0x%X: string 'offset' not found\n");
        }
    }
    else
    {
        msg("ea: 0x%X, flags = 0x%X is not a pointer\n", ea, f);
    }

    return 0;
}

//-----------------------------------------------------------------------
static RegisterHotkeys()
{
    msg("\n------------------------------ HTCHotkeys --------------------------------------\n");

    del_idc_hotkey("Shift+U");
    add_idc_hotkey("Shift+U", "CreateUnicodeString");
    msg("Shift+U: create Unicode string\n");

    del_idc_hotkey("Alt+Shift+Up");
    add_idc_hotkey("Alt+Shift+Up", "JumpToBeginOfFunction");
    msg("Alt+Shift+Up: jump to begin of current function\n");

    del_idc_hotkey("Alt+Shift+Down");
    add_idc_hotkey("Alt+Shift+Down", "JumpToEndOfFunction");
    msg("Alt+Shift+Down: jump to end of current function\n");

    del_idc_hotkey("Ctrl+Alt+Up");
    add_idc_hotkey("Ctrl+Alt+Up", "JumpToPrevLabel");
    msg("Ctrl+Alt+Up: jump to previous label\n");

    del_idc_hotkey("Ctrl+Alt+Down");
    add_idc_hotkey("Ctrl+Alt+Down", "JumpToNextLabel");
    msg("Ctrl+Alt+Down: jump to next label\n");

    del_idc_hotkey("Shift+P");
    add_idc_hotkey("Shift+P", "NamePointer");
    msg("Shift+P: name pointer\n");

    // Appcalls, only enable in PE mode
    if (FT_PE == get_inf_attr(INF_FILETYPE))
    {
        last_cmd = "";
        add_idc_hotkey("Ctrl-Alt-F9", "Appcall_Start");
        msg("Ctrl-Alt-F9: Appcall_Start\n");
        add_idc_hotkey("Ctrl-Alt-F10", "cleanup_appcall");
        msg("Ctrl-Alt-F10: cleanup_appcall\n");
        add_idc_hotkey("Ctrl-Alt-F4", "Appcall_Here");
        msg("Ctrl-Alt-F4: Appcall_Here\n");
    }

    msg("--------------------------------------------------------------------------------\n\n");
}

// HTC - end
//

//-----------------------------------------------------------------------
static main(void)
{
    //
    // This function is executed when IDA is started.
    //
    // Add statements to fine-tune your IDA here.
    //

    // Instantiate the breakpoints singleton object
    Breakpoints = BreakpointManager();

    // uncomment this line to remove full paths in the debugger process options:
    set_inf_attr(INF_LFLAGS, LFLG_DBG_NOPATH | get_inf_attr(INF_LFLAGS));

    // HTC
    RegisterHotkeys();

    // idauser.idc should define user_main(), call it here.
    auto e;
    try
    {
        user_main();
    }
    catch (e)
    {
        // if idauser.idc did not exist, silently ignore the call error.
        if (e.description != "Attempt to call undefined function 'user_main'")
        {
            throw e;
        }
    }
}
