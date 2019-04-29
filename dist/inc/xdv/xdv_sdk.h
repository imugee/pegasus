#ifndef __DEFINE_XCN_SDK__
#define __DEFINE_XCN_SDK__

#include <list>
#include <vector>
#include <map>
#include <set>
#include <initializer_list>
#include <memory>
#include <string>
#include <mutex>
#include <regex>

// --------------------------------------------------------
// 
typedef int xdv_handle;
class IPlugin;
typedef void(*PluginFunctionType)(IPlugin *object, void *ctx);

// --------------------------------------------------------
// 
#define MAX_COMMAND_LENGTH	1024

typedef struct _tags_xcn_var
{
	char tag[50];
}xvar, *pxvar;

// --------------------------------------------------------
// 
#ifdef _WINDLL
#define XDV_WINDOWS_EXPORT				__declspec(dllexport)
#else
#define XDV_WINDOWS_EXPORT
#endif

// --------------------------------------------------------
// 
typedef xvar(*ExtensionFunctionT)(int, char *[]);
#define EXTS_FUNC(function_name)	extern "C" __declspec(dllexport) xvar function_name(int argc, char * argv[]) // 
typedef xdv_handle(*AddInterfaceType)();

// --------------------------------------------------------
// 
#define NAMESPACE_B(name)	namespace name {
#define NAMESPACE_E(name)	}

#define XCN_NAMESPACE_B(name)				NAMESPACE_B(xdv) NAMESPACE_B(name) 
#define XCN_NAMESPACE_E(name)				NAMESPACE_E(name) NAMESPACE_E(xdv)

// --------------------------------------------------------
// 
XCN_NAMESPACE_B(status)
typedef enum _tag_update_status_id
{
	XENOM_UPDATE_STATUS_UP = -1,
	XENOM_UPDATE_STATUS_DOWN = 1,

	XENOM_UPDATE_STATUS_PRE_EVENT,
	XENOM_UPDATE_STATUS_DOUBLE_CLICK_POST_EVENT,

	XENOM_UPDATE_STSTUS_BACKSPACE,
	XENOM_UPDATE_STSTUS_SPACE_POST_EVENT,

	XENOM_UPDATE_STATUS_SHORTCUT = 10
}id;
XCN_NAMESPACE_E(status)


XCN_NAMESPACE_B(key)
typedef enum _tag_key_id
{
	Key_A = 0x41,
	Key_B = 0x42,
	Key_C = 0x43,
	Key_D = 0x44,
	Key_E = 0x45,
	Key_F = 0x46,
	Key_G = 0x47,
	Key_H = 0x48,
	Key_I = 0x49,
	Key_J = 0x4a,
	Key_K = 0x4b,
	Key_L = 0x4c,
	Key_M = 0x4d,
	Key_N = 0x4e,
	Key_O = 0x4f,
	Key_P = 0x50,
	Key_Q = 0x51,
	Key_R = 0x52,
	Key_S = 0x53,
	Key_T = 0x54,
	Key_U = 0x55,
	Key_V = 0x56,
	Key_W = 0x57,
	Key_X = 0x58,
	Key_Y = 0x59,
	Key_Z = 0x5a,

	Key_F1 = 0x01000030,                // function keys
	Key_F2 = 0x01000031,
	Key_F3 = 0x01000032,
	Key_F4 = 0x01000033,
	Key_F5 = 0x01000034,
	Key_F6 = 0x01000035,
	Key_F7 = 0x01000036,
	Key_F8 = 0x01000037,
	Key_F9 = 0x01000038,
	Key_F10 = 0x01000039,
	Key_F11 = 0x0100003a,
	Key_F12 = 0x0100003b,

	Key_SHIFT = 0x02000000,
	Key_CTRL = 0x04000000,
	Key_ALT = 0x08000000,
}id;
XCN_NAMESPACE_E(key)


// --------------------------------------------------------
// 
XCN_NAMESPACE_B(object)
typedef enum _tag_object_id
{
	XENOM_NO_OBJECT,
	XENOM_PLUGIN_OBJECT,

	XENOM_X86_ARCHITECTURE_OBJECT,
	XENOM_X64_ARCHITECTURE_OBJECT,

	XENOM_X86_ANALYZER_OBJECT,
	XENOM_X64_ANALYZER_OBJECT,

	XENOM_PARSER_SYSTEM_OBJECT,
	XENOM_DEBUGGER_SYSTEM_OBJECT,

	XENOM_WORKER_OBJECT,
	XENOM_VIEWER_OBJECT
}id;
XCN_NAMESPACE_E(object)

// --------------------------------------------------------
// 
XCN_NAMESPACE_B(handle)
#define xdv_handle_TABLE_MAX_IDX 15
typedef enum _tag_xdv_handle_idx_id
{
	xdv_handle_PARSER_IDX,
	xdv_handle_ARCH_IDX,
	xdv_handle_VIEWER_IDX
}id;
XCN_NAMESPACE_E(handle)

// --------------------------------------------------------
// 
XCN_NAMESPACE_B(architecture)
NAMESPACE_B(x86)
NAMESPACE_B(block)
typedef enum _tag_bock_id
{
	X86_ANALYZE_FAIL,
	X86_CODE_BLOCK,
	X86_DEBUG_TRAP,
	X86_DATA_BLOCK,
	X86_UNKNOWN_BLOCK
}id;
NAMESPACE_E(block)
NAMESPACE_B(operand)
typedef struct _tag_x86_operand_information_type
{
	long id;
	long long value;
}type;

typedef enum x86_operand_id
{
	X86_OP_INVALID = 0,
	X86_OP_REG,
	X86_OP_IMM,
	X86_OP_MEM,
	X86_OP_FP
} id;
NAMESPACE_E(operand)

NAMESPACE_B(context)
typedef enum
{
	DBG_X86_REG_IDX_GS
	, DBG_X86_REG_IDX_FS
	, DBG_X86_REG_IDX_ES
	, DBG_X86_REG_IDX_DS
	, DBG_X86_REG_IDX_EDI
	, DBG_X86_REG_IDX_ESI
	, DBG_X86_REG_IDX_EBX
	, DBG_X86_REG_IDX_EDX
	, DBG_X86_REG_IDX_ECX
	, DBG_X86_REG_IDX_EAX
	, DBG_X86_REG_IDX_EBP
	, DBG_X86_REG_IDX_EIP
	, DBG_X86_REG_IDX_CS
	, DBG_X86_REG_IDX_EFL
	, DBG_X86_REG_IDX_ESP
	, DBG_X86_REG_IDX_SS
	, DBG_X86_REG_IDX_DR0
	, DBG_X86_REG_IDX_DR1
	, DBG_X86_REG_IDX_DR2
	, DBG_X86_REG_IDX_DR3
	, DBG_X86_REG_IDX_DR6
	, DBG_X86_REG_IDX_DR7
	, DBG_X86_REG_IDX_DI
	, DBG_X86_REG_IDX_SI
	, DBG_X86_REG_IDX_BX
	, DBG_X86_REG_IDX_DX
	, DBG_X86_REG_IDX_CX
	, DBG_X86_REG_IDX_AX
	, DBG_X86_REG_IDX_BP
	, DBG_X86_REG_IDX_IP
	, DBG_X86_REG_IDX_FL
	, DBG_X86_REG_IDX_SP
	, DBG_X86_REG_IDX_BL
	, DBG_X86_REG_IDX_DL
	, DBG_X86_REG_IDX_CL
	, DBG_X86_REG_IDX_AL
	, DBG_X86_REG_IDX_BH
	, DBG_X86_REG_IDX_DH
	, DBG_X86_REG_IDX_CH
	, DBG_X86_REG_IDX_AH
	, DBG_X86_REG_IDX_FPCW
	, DBG_X86_REG_IDX_FPSW
	, DBG_X86_REG_IDX_FPTW
	, DBG_X86_REG_IDX_FOPCODE
	, DBG_X86_REG_IDX_FPIP
	, DBG_X86_REG_IDX_FPIPSEL
	, DBG_X86_REG_IDX_FPDP
	, DBG_X86_REG_IDX_FPDPSEL
	, DBG_X86_REG_IDX_ST0
	, DBG_X86_REG_IDX_ST1
	, DBG_X86_REG_IDX_ST2
	, DBG_X86_REG_IDX_ST3
	, DBG_X86_REG_IDX_ST4
	, DBG_X86_REG_IDX_ST5
	, DBG_X86_REG_IDX_ST6
	, DBG_X86_REG_IDX_ST7
	, DBG_X86_REG_IDX_MM0
	, DBG_X86_REG_IDX_MM1
	, DBG_X86_REG_IDX_MM2
	, DBG_X86_REG_IDX_MM3
	, DBG_X86_REG_IDX_MM4
	, DBG_X86_REG_IDX_MM5
	, DBG_X86_REG_IDX_MM6
	, DBG_X86_REG_IDX_MM7
	, DBG_X86_REG_IDX_MXCSR
	, DBG_X86_REG_IDX_XMM0
	, DBG_X86_REG_IDX_XMM1
	, DBG_X86_REG_IDX_XMM2
	, DBG_X86_REG_IDX_XMM3
	, DBG_X86_REG_IDX_XMM4
	, DBG_X86_REG_IDX_XMM5
	, DBG_X86_REG_IDX_XMM6
	, DBG_X86_REG_IDX_XMM7
	, DBG_X86_REG_IDX_IOPL
	, DBG_X86_REG_IDX_OF
	, DBG_X86_REG_IDX_DF
	, DBG_X86_REG_IDX_IF
	, DBG_X86_REG_IDX_TF
	, DBG_X86_REG_IDX_SF
	, DBG_X86_REG_IDX_ZF
	, DBG_X86_REG_IDX_AF
	, DBG_X86_REG_IDX_PF
	, DBG_X86_REG_IDX_CF
	, DBG_X86_REG_IDX_VIP
	, DBG_X86_REG_IDX_VIF
	, DBG_X86_REG_IDX_XMM0L
	, DBG_X86_REG_IDX_XMM1L
	, DBG_X86_REG_IDX_XMM2L
	, DBG_X86_REG_IDX_XMM3L
	, DBG_X86_REG_IDX_XMM4L
	, DBG_X86_REG_IDX_XMM5L
	, DBG_X86_REG_IDX_XMM6L
	, DBG_X86_REG_IDX_XMM7L
	, DBG_X86_REG_IDX_XMM0H
	, DBG_X86_REG_IDX_XMM1H
	, DBG_X86_REG_IDX_XMM2H
	, DBG_X86_REG_IDX_XMM3H
	, DBG_X86_REG_IDX_XMM4H
	, DBG_X86_REG_IDX_XMM5H
	, DBG_X86_REG_IDX_XMM6H
	, DBG_X86_REG_IDX_XMM7H
	, DBG_X86_REG_IDX_XMM0D0
	, DBG_X86_REG_IDX_XMM0D1
	, DBG_X86_REG_IDX_XMM0D2
	, DBG_X86_REG_IDX_XMM0D3
	, DBG_X86_REG_IDX_XMM1D0
	, DBG_X86_REG_IDX_XMM1D1
	, DBG_X86_REG_IDX_XMM1D2
	, DBG_X86_REG_IDX_XMM1D3
	, DBG_X86_REG_IDX_XMM2D0
	, DBG_X86_REG_IDX_XMM2D1
	, DBG_X86_REG_IDX_XMM2D2
	, DBG_X86_REG_IDX_XMM2D3
	, DBG_X86_REG_IDX_XMM3D0
	, DBG_X86_REG_IDX_XMM3D1
	, DBG_X86_REG_IDX_XMM3D2
	, DBG_X86_REG_IDX_XMM3D3
	, DBG_X86_REG_IDX_XMM4D0
	, DBG_X86_REG_IDX_XMM4D1
	, DBG_X86_REG_IDX_XMM4D2
	, DBG_X86_REG_IDX_XMM4D3
	, DBG_X86_REG_IDX_XMM5D0
	, DBG_X86_REG_IDX_XMM5D1
	, DBG_X86_REG_IDX_XMM5D2
	, DBG_X86_REG_IDX_XMM5D3
	, DBG_X86_REG_IDX_XMM6D0
	, DBG_X86_REG_IDX_XMM6D1
	, DBG_X86_REG_IDX_XMM6D2
	, DBG_X86_REG_IDX_XMM6D3
	, DBG_X86_REG_IDX_XMM7D0
	, DBG_X86_REG_IDX_XMM7D1
	, DBG_X86_REG_IDX_XMM7D2
	, DBG_X86_REG_IDX_XMM7D3
	, DBG_X86_REG_IDX_YMM0
	, DBG_X86_REG_IDX_YMM1
	, DBG_X86_REG_IDX_YMM2
	, DBG_X86_REG_IDX_YMM3
	, DBG_X86_REG_IDX_YMM4
	, DBG_X86_REG_IDX_YMM5
	, DBG_X86_REG_IDX_YMM6
	, DBG_X86_REG_IDX_YMM7
	, DBG_X86_REG_IDX_YMM0L
	, DBG_X86_REG_IDX_YMM1L
	, DBG_X86_REG_IDX_YMM2L
	, DBG_X86_REG_IDX_YMM3L
	, DBG_X86_REG_IDX_YMM4L
	, DBG_X86_REG_IDX_YMM5L
	, DBG_X86_REG_IDX_YMM6L
	, DBG_X86_REG_IDX_YMM7L
	, DBG_X86_REG_IDX_YMM0H
	, DBG_X86_REG_IDX_YMM1H
	, DBG_X86_REG_IDX_YMM2H
	, DBG_X86_REG_IDX_YMM3H
	, DBG_X86_REG_IDX_YMM4H
	, DBG_X86_REG_IDX_YMM5H
	, DBG_X86_REG_IDX_YMM6H
	, DBG_X86_REG_IDX_YMM7H
	, DBG_X86_REG_IDX_YMM0D0
	, DBG_X86_REG_IDX_YMM0D1
	, DBG_X86_REG_IDX_YMM0D2
	, DBG_X86_REG_IDX_YMM0D3
	, DBG_X86_REG_IDX_YMM1D0
	, DBG_X86_REG_IDX_YMM1D1
	, DBG_X86_REG_IDX_YMM1D2
	, DBG_X86_REG_IDX_YMM1D3
	, DBG_X86_REG_IDX_YMM2D0
	, DBG_X86_REG_IDX_YMM2D1
	, DBG_X86_REG_IDX_YMM2D2
	, DBG_X86_REG_IDX_YMM2D3
	, DBG_X86_REG_IDX_YMM3D0
	, DBG_X86_REG_IDX_YMM3D1
	, DBG_X86_REG_IDX_YMM3D2
	, DBG_X86_REG_IDX_YMM3D3
	, DBG_X86_REG_IDX_YMM4D0
	, DBG_X86_REG_IDX_YMM4D1
	, DBG_X86_REG_IDX_YMM4D2
	, DBG_X86_REG_IDX_YMM4D3
	, DBG_X86_REG_IDX_YMM5D0
	, DBG_X86_REG_IDX_YMM5D1
	, DBG_X86_REG_IDX_YMM5D2
	, DBG_X86_REG_IDX_YMM5D3
	, DBG_X86_REG_IDX_YMM6D0
	, DBG_X86_REG_IDX_YMM6D1
	, DBG_X86_REG_IDX_YMM6D2
	, DBG_X86_REG_IDX_YMM6D3
	, DBG_X86_REG_IDX_YMM7D0
	, DBG_X86_REG_IDX_YMM7D1
	, DBG_X86_REG_IDX_YMM7D2
	, DBG_X86_REG_IDX_YMM7D3
}x86idx;

typedef enum
{
	DBG_X64_REG_IDX_RAX
	, DBG_X64_REG_IDX_RCX
	, DBG_X64_REG_IDX_RDX
	, DBG_X64_REG_IDX_RBX
	, DBG_X64_REG_IDX_RSP
	, DBG_X64_REG_IDX_RBP
	, DBG_X64_REG_IDX_RSI
	, DBG_X64_REG_IDX_RDI
	, DBG_X64_REG_IDX_R8
	, DBG_X64_REG_IDX_R9
	, DBG_X64_REG_IDX_R10
	, DBG_X64_REG_IDX_R11
	, DBG_X64_REG_IDX_R12
	, DBG_X64_REG_IDX_R13
	, DBG_X64_REG_IDX_R14
	, DBG_X64_REG_IDX_R15
	, DBG_X64_REG_IDX_RIP
	, DBG_X64_REG_IDX_EFL
	, DBG_X64_REG_IDX_CS
	, DBG_X64_REG_IDX_DS
	, DBG_X64_REG_IDX_ES
	, DBG_X64_REG_IDX_FS
	, DBG_X64_REG_IDX_GS
	, DBG_X64_REG_IDX_SS
	, DBG_X64_REG_IDX_DR0
	, DBG_X64_REG_IDX_DR1
	, DBG_X64_REG_IDX_DR2
	, DBG_X64_REG_IDX_DR3
	, DBG_X64_REG_IDX_DR6
	, DBG_X64_REG_IDX_DR7
	, DBG_X64_REG_IDX_FPCW
	, DBG_X64_REG_IDX_FPSW
	, DBG_X64_REG_IDX_FPTW
	, DBG_X64_REG_IDX_ST0
	, DBG_X64_REG_IDX_ST1
	, DBG_X64_REG_IDX_ST2
	, DBG_X64_REG_IDX_ST3
	, DBG_X64_REG_IDX_ST4
	, DBG_X64_REG_IDX_ST5
	, DBG_X64_REG_IDX_ST6
	, DBG_X64_REG_IDX_ST7
	, DBG_X64_REG_IDX_MM0
	, DBG_X64_REG_IDX_MM1
	, DBG_X64_REG_IDX_MM2
	, DBG_X64_REG_IDX_MM3
	, DBG_X64_REG_IDX_MM4
	, DBG_X64_REG_IDX_MM5
	, DBG_X64_REG_IDX_MM6
	, DBG_X64_REG_IDX_MM7
	, DBG_X64_REG_IDX_MXCSR
	, DBG_X64_REG_IDX_XMM0
	, DBG_X64_REG_IDX_XMM1
	, DBG_X64_REG_IDX_XMM2
	, DBG_X64_REG_IDX_XMM3
	, DBG_X64_REG_IDX_XMM4
	, DBG_X64_REG_IDX_XMM5
	, DBG_X64_REG_IDX_XMM6
	, DBG_X64_REG_IDX_XMM7
	, DBG_X64_REG_IDX_XMM8
	, DBG_X64_REG_IDX_XMM9
	, DBG_X64_REG_IDX_XMM10
	, DBG_X64_REG_IDX_XMM11
	, DBG_X64_REG_IDX_XMM12
	, DBG_X64_REG_IDX_XMM13
	, DBG_X64_REG_IDX_XMM14
	, DBG_X64_REG_IDX_XMM15
	, DBG_X64_REG_IDX_XMM0D0
	, DBG_X64_REG_IDX_XMM0D1
	, DBG_X64_REG_IDX_XMM0D2
	, DBG_X64_REG_IDX_XMM0D3
	, DBG_X64_REG_IDX_XMM1D0
	, DBG_X64_REG_IDX_XMM1D1
	, DBG_X64_REG_IDX_XMM1D2
	, DBG_X64_REG_IDX_XMM1D3
	, DBG_X64_REG_IDX_XMM2D0
	, DBG_X64_REG_IDX_XMM2D1
	, DBG_X64_REG_IDX_XMM2D2
	, DBG_X64_REG_IDX_XMM2D3
	, DBG_X64_REG_IDX_XMM3D0
	, DBG_X64_REG_IDX_XMM3D1
	, DBG_X64_REG_IDX_XMM3D2
	, DBG_X64_REG_IDX_XMM3D3
	, DBG_X64_REG_IDX_XMM4D0
	, DBG_X64_REG_IDX_XMM4D1
	, DBG_X64_REG_IDX_XMM4D2
	, DBG_X64_REG_IDX_XMM4D3
	, DBG_X64_REG_IDX_XMM5D0
	, DBG_X64_REG_IDX_XMM5D1
	, DBG_X64_REG_IDX_XMM5D2
	, DBG_X64_REG_IDX_XMM5D3
	, DBG_X64_REG_IDX_XMM6D0
	, DBG_X64_REG_IDX_XMM6D1
	, DBG_X64_REG_IDX_XMM6D2
	, DBG_X64_REG_IDX_XMM6D3
	, DBG_X64_REG_IDX_XMM7D0
	, DBG_X64_REG_IDX_XMM7D1
	, DBG_X64_REG_IDX_XMM7D2
	, DBG_X64_REG_IDX_XMM7D3
	, DBG_X64_REG_IDX_XMM8D0
	, DBG_X64_REG_IDX_XMM8D1
	, DBG_X64_REG_IDX_XMM8D2
	, DBG_X64_REG_IDX_XMM8D3
	, DBG_X64_REG_IDX_XMM9D0
	, DBG_X64_REG_IDX_XMM9D1
	, DBG_X64_REG_IDX_XMM9D2
	, DBG_X64_REG_IDX_XMM9D3
	, DBG_X64_REG_IDX_XMM10D0
	, DBG_X64_REG_IDX_XMM10D1
	, DBG_X64_REG_IDX_XMM10D2
	, DBG_X64_REG_IDX_XMM10D3
	, DBG_X64_REG_IDX_XMM11D0
	, DBG_X64_REG_IDX_XMM11D1
	, DBG_X64_REG_IDX_XMM11D2
	, DBG_X64_REG_IDX_XMM11D3
	, DBG_X64_REG_IDX_XMM12D0
	, DBG_X64_REG_IDX_XMM12D1
	, DBG_X64_REG_IDX_XMM12D2
	, DBG_X64_REG_IDX_XMM12D3
	, DBG_X64_REG_IDX_XMM13D0
	, DBG_X64_REG_IDX_XMM13D1
	, DBG_X64_REG_IDX_XMM13D2
	, DBG_X64_REG_IDX_XMM13D3
	, DBG_X64_REG_IDX_XMM14D0
	, DBG_X64_REG_IDX_XMM14D1
	, DBG_X64_REG_IDX_XMM14D2
	, DBG_X64_REG_IDX_XMM14D3
	, DBG_X64_REG_IDX_XMM15D0
	, DBG_X64_REG_IDX_XMM15D1
	, DBG_X64_REG_IDX_XMM15D2
	, DBG_X64_REG_IDX_XMM15D3
	, DBG_X64_REG_IDX_XMM0L
	, DBG_X64_REG_IDX_XMM1L
	, DBG_X64_REG_IDX_XMM2L
	, DBG_X64_REG_IDX_XMM3L
	, DBG_X64_REG_IDX_XMM4L
	, DBG_X64_REG_IDX_XMM5L
	, DBG_X64_REG_IDX_XMM6L
	, DBG_X64_REG_IDX_XMM7L
	, DBG_X64_REG_IDX_XMM8L
	, DBG_X64_REG_IDX_XMM9L
	, DBG_X64_REG_IDX_XMM10L
	, DBG_X64_REG_IDX_XMM11L
	, DBG_X64_REG_IDX_XMM12L
	, DBG_X64_REG_IDX_XMM13L
	, DBG_X64_REG_IDX_XMM14L
	, DBG_X64_REG_IDX_XMM15L
	, DBG_X64_REG_IDX_XMM0H
	, DBG_X64_REG_IDX_XMM1H
	, DBG_X64_REG_IDX_XMM2H
	, DBG_X64_REG_IDX_XMM3H
	, DBG_X64_REG_IDX_XMM4H
	, DBG_X64_REG_IDX_XMM5H
	, DBG_X64_REG_IDX_XMM6H
	, DBG_X64_REG_IDX_XMM7H
	, DBG_X64_REG_IDX_XMM8H
	, DBG_X64_REG_IDX_XMM9H
	, DBG_X64_REG_IDX_XMM10H
	, DBG_X64_REG_IDX_XMM11H
	, DBG_X64_REG_IDX_XMM12H
	, DBG_X64_REG_IDX_XMM13H
	, DBG_X64_REG_IDX_XMM14H
	, DBG_X64_REG_IDX_XMM15H
	, DBG_X64_REG_IDX_YMM0
	, DBG_X64_REG_IDX_YMM1
	, DBG_X64_REG_IDX_YMM2
	, DBG_X64_REG_IDX_YMM3
	, DBG_X64_REG_IDX_YMM4
	, DBG_X64_REG_IDX_YMM5
	, DBG_X64_REG_IDX_YMM6
	, DBG_X64_REG_IDX_YMM7
	, DBG_X64_REG_IDX_YMM8
	, DBG_X64_REG_IDX_YMM9
	, DBG_X64_REG_IDX_YMM10
	, DBG_X64_REG_IDX_YMM11
	, DBG_X64_REG_IDX_YMM12
	, DBG_X64_REG_IDX_YMM13
	, DBG_X64_REG_IDX_YMM14
	, DBG_X64_REG_IDX_YMM15
	, DBG_X64_REG_IDX_YMM0D0
	, DBG_X64_REG_IDX_YMM0D1
	, DBG_X64_REG_IDX_YMM0D2
	, DBG_X64_REG_IDX_YMM0D3
	, DBG_X64_REG_IDX_YMM1D0
	, DBG_X64_REG_IDX_YMM1D1
	, DBG_X64_REG_IDX_YMM1D2
	, DBG_X64_REG_IDX_YMM1D3
	, DBG_X64_REG_IDX_YMM2D0
	, DBG_X64_REG_IDX_YMM2D1
	, DBG_X64_REG_IDX_YMM2D2
	, DBG_X64_REG_IDX_YMM2D3
	, DBG_X64_REG_IDX_YMM3D0
	, DBG_X64_REG_IDX_YMM3D1
	, DBG_X64_REG_IDX_YMM3D2
	, DBG_X64_REG_IDX_YMM3D3
	, DBG_X64_REG_IDX_YMM4D0
	, DBG_X64_REG_IDX_YMM4D1
	, DBG_X64_REG_IDX_YMM4D2
	, DBG_X64_REG_IDX_YMM4D3
	, DBG_X64_REG_IDX_YMM5D0
	, DBG_X64_REG_IDX_YMM5D1
	, DBG_X64_REG_IDX_YMM5D2
	, DBG_X64_REG_IDX_YMM5D3
	, DBG_X64_REG_IDX_YMM6D0
	, DBG_X64_REG_IDX_YMM6D1
	, DBG_X64_REG_IDX_YMM6D2
	, DBG_X64_REG_IDX_YMM6D3
	, DBG_X64_REG_IDX_YMM7D0
	, DBG_X64_REG_IDX_YMM7D1
	, DBG_X64_REG_IDX_YMM7D2
	, DBG_X64_REG_IDX_YMM7D3
	, DBG_X64_REG_IDX_YMM8D0
	, DBG_X64_REG_IDX_YMM8D1
	, DBG_X64_REG_IDX_YMM8D2
	, DBG_X64_REG_IDX_YMM8D3
	, DBG_X64_REG_IDX_YMM9D0
	, DBG_X64_REG_IDX_YMM9D1
	, DBG_X64_REG_IDX_YMM9D2
	, DBG_X64_REG_IDX_YMM9D3
	, DBG_X64_REG_IDX_YMM10D0
	, DBG_X64_REG_IDX_YMM10D1
	, DBG_X64_REG_IDX_YMM10D2
	, DBG_X64_REG_IDX_YMM10D3
	, DBG_X64_REG_IDX_YMM11D0
	, DBG_X64_REG_IDX_YMM11D1
	, DBG_X64_REG_IDX_YMM11D2
	, DBG_X64_REG_IDX_YMM11D3
	, DBG_X64_REG_IDX_YMM12D0
	, DBG_X64_REG_IDX_YMM12D1
	, DBG_X64_REG_IDX_YMM12D2
	, DBG_X64_REG_IDX_YMM12D3
	, DBG_X64_REG_IDX_YMM13D0
	, DBG_X64_REG_IDX_YMM13D1
	, DBG_X64_REG_IDX_YMM13D2
	, DBG_X64_REG_IDX_YMM13D3
	, DBG_X64_REG_IDX_YMM14D0
	, DBG_X64_REG_IDX_YMM14D1
	, DBG_X64_REG_IDX_YMM14D2
	, DBG_X64_REG_IDX_YMM14D3
	, DBG_X64_REG_IDX_YMM15D0
	, DBG_X64_REG_IDX_YMM15D1
	, DBG_X64_REG_IDX_YMM15D2
	, DBG_X64_REG_IDX_YMM15D3
	, DBG_X64_REG_IDX_YMM0L
	, DBG_X64_REG_IDX_YMM1L
	, DBG_X64_REG_IDX_YMM2L
	, DBG_X64_REG_IDX_YMM3L
	, DBG_X64_REG_IDX_YMM4L
	, DBG_X64_REG_IDX_YMM5L
	, DBG_X64_REG_IDX_YMM6L
	, DBG_X64_REG_IDX_YMM7L
	, DBG_X64_REG_IDX_YMM8L
	, DBG_X64_REG_IDX_YMM9L
	, DBG_X64_REG_IDX_YMM10L
	, DBG_X64_REG_IDX_YMM11L
	, DBG_X64_REG_IDX_YMM12L
	, DBG_X64_REG_IDX_YMM13L
	, DBG_X64_REG_IDX_YMM14L
	, DBG_X64_REG_IDX_YMM15L
	, DBG_X64_REG_IDX_YMM0H
	, DBG_X64_REG_IDX_YMM1H
	, DBG_X64_REG_IDX_YMM2H
	, DBG_X64_REG_IDX_YMM3H
	, DBG_X64_REG_IDX_YMM4H
	, DBG_X64_REG_IDX_YMM5H
	, DBG_X64_REG_IDX_YMM6H
	, DBG_X64_REG_IDX_YMM7H
	, DBG_X64_REG_IDX_YMM8H
	, DBG_X64_REG_IDX_YMM9H
	, DBG_X64_REG_IDX_YMM10H
	, DBG_X64_REG_IDX_YMM11H
	, DBG_X64_REG_IDX_YMM12H
	, DBG_X64_REG_IDX_YMM13H
	, DBG_X64_REG_IDX_YMM14H
	, DBG_X64_REG_IDX_YMM15H
	, DBG_X64_REG_IDX_EXFORM
	, DBG_X64_REG_IDX_EXTO
	, DBG_X64_REG_IDX_BRFROM
	, DBG_X64_REG_IDX_BRTO
	, DBG_X64_REG_IDX_EAX
	, DBG_X64_REG_IDX_ECX
	, DBG_X64_REG_IDX_EDX
	, DBG_X64_REG_IDX_EBX
	, DBG_X64_REG_IDX_ESP
	, DBG_X64_REG_IDX_EBP
	, DBG_X64_REG_IDX_ESI
	, DBG_X64_REG_IDX_EDI
	, DBG_X64_REG_IDX_R8D
	, DBG_X64_REG_IDX_R9D
	, DBG_X64_REG_IDX_R10D
	, DBG_X64_REG_IDX_R11D
	, DBG_X64_REG_IDX_R12D
	, DBG_X64_REG_IDX_R13D
	, DBG_X64_REG_IDX_R14D
	, DBG_X64_REG_IDX_R15D
	, DBG_X64_REG_IDX_EIP
	, DBG_X64_REG_IDX_AX
	, DBG_X64_REG_IDX_CX
	, DBG_X64_REG_IDX_DX
	, DBG_X64_REG_IDX_BX
	, DBG_X64_REG_IDX_SP
	, DBG_X64_REG_IDX_BP
	, DBG_X64_REG_IDX_SI
	, DBG_X64_REG_IDX_DI
	, DBG_X64_REG_IDX_R8W
	, DBG_X64_REG_IDX_R9W
	, DBG_X64_REG_IDX_R10W
	, DBG_X64_REG_IDX_R11W
	, DBG_X64_REG_IDX_R12W
	, DBG_X64_REG_IDX_R13W
	, DBG_X64_REG_IDX_R14W
	, DBG_X64_REG_IDX_R15W
	, DBG_X64_REG_IDX_IP
	, DBG_X64_REG_IDX_FL
	, DBG_X64_REG_IDX_AL
	, DBG_X64_REG_IDX_CL
	, DBG_X64_REG_IDX_DL
	, DBG_X64_REG_IDX_BL
	, DBG_X64_REG_IDX_SPL
	, DBG_X64_REG_IDX_BPL
	, DBG_X64_REG_IDX_SIL
	, DBG_X64_REG_IDX_DIL
	, DBG_X64_REG_IDX_R8B
	, DBG_X64_REG_IDX_R9B
	, DBG_X64_REG_IDX_R10B
	, DBG_X64_REG_IDX_R11B
	, DBG_X64_REG_IDX_R12B
	, DBG_X64_REG_IDX_R13B
	, DBG_X64_REG_IDX_R14B
	, DBG_X64_REG_IDX_R15B
	, DBG_X64_REG_IDX_AH
	, DBG_X64_REG_IDX_CH
	, DBG_X64_REG_IDX_DH
	, DBG_X64_REG_IDX_BH
	, DBG_X64_REG_IDX_IOPL
	, DBG_X64_REG_IDX_OF
	, DBG_X64_REG_IDX_DF
	, DBG_X64_REG_IDX_IF
	, DBG_X64_REG_IDX_TF
	, DBG_X64_REG_IDX_SF
	, DBG_X64_REG_IDX_ZF
	, DBG_X64_REG_IDX_AF
	, DBG_X64_REG_IDX_PF
	, DBG_X64_REG_IDX_CF
	, DBG_X64_REG_IDX_VIP
	, DBG_X64_REG_IDX_VIF
}x64idx;

typedef struct __DBG_THREAD_CONTEXT
{
	unsigned long long rax;
	unsigned long long rcx;
	unsigned long long rdx;
	unsigned long long rbx;

	unsigned long long rsp;
	unsigned long long rbp;

	unsigned long long rsi;
	unsigned long long rdi;

	unsigned long long r8;
	unsigned long long r9;
	unsigned long long r10;
	unsigned long long r11;
	unsigned long long r12;
	unsigned long long r13;
	unsigned long long r14;
	unsigned long long r15;

	unsigned long long rip;

	unsigned long efl;

	unsigned long cs;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
	unsigned long ss;

	unsigned long long dr0;
	unsigned long long dr1;
	unsigned long long dr2;
	unsigned long long dr3;
	unsigned long long dr6;
	unsigned long long dr7;

	unsigned long long fpcw;
	unsigned long long fpsw;
	unsigned long long fptw;

	unsigned long long st0;
	unsigned long long st1;
	unsigned long long st2;
	unsigned long long st3;
	unsigned long long st4;
	unsigned long long st5;
	unsigned long long st6;
	unsigned long long st7;

	unsigned long long mm0;
	unsigned long long mm1;
	unsigned long long mm2;
	unsigned long long mm3;
	unsigned long long mm4;
	unsigned long long mm5;
	unsigned long long mm6;
	unsigned long long mm7;

	unsigned long long mxcsr;

	unsigned long long xmm0;
	unsigned long long xmm1;
	unsigned long long xmm2;
	unsigned long long xmm3;
	unsigned long long xmm4;
	unsigned long long xmm5;
	unsigned long long xmm6;
	unsigned long long xmm7;
	unsigned long long xmm8;
	unsigned long long xmm9;
	unsigned long long xmm10;
	unsigned long long xmm11;
	unsigned long long xmm12;
	unsigned long long xmm13;
	unsigned long long xmm14;
	unsigned long long xmm15;

	unsigned long long ymm0;
	unsigned long long ymm1;
	unsigned long long ymm2;
	unsigned long long ymm3;
	unsigned long long ymm4;
	unsigned long long ymm5;
	unsigned long long ymm6;
	unsigned long long ymm7;
	unsigned long long ymm8;
	unsigned long long ymm9;
	unsigned long long ymm10;
	unsigned long long ymm11;
	unsigned long long ymm12;
	unsigned long long ymm13;
	unsigned long long ymm14;
	unsigned long long ymm15;

	unsigned long long iopl;
	unsigned long long vip;
	unsigned long long vif;

	unsigned char extended[512]; // windows context
}type;
NAMESPACE_E(context)

NAMESPACE_B(frame)
typedef struct _tag_stack_frame_type
{
	unsigned long long instruction_offset;
	unsigned long long return_offset;
	unsigned long long frame_offset;
	unsigned long long stack_offset;
	unsigned long long func_table_entry;
	unsigned long long params[4];
	unsigned long long reserved[6];
	int bool_virtual;
	unsigned long frame_number;
} type, *type_ptr;
NAMESPACE_E(frame)

typedef struct _tag_x86_arch_type
{
	unsigned long instruction_id;
	unsigned long instruction_size;
	unsigned long instruction_group;

	unsigned long operand_count;
	architecture::x86::operand::type operands[8];
}type, *type_ptr;
NAMESPACE_E(x86)
XCN_NAMESPACE_E(architecture)

// --------------------------------------------------------
// 
XCN_NAMESPACE_B(memory)
typedef struct _tag_memory_type
{
	unsigned long long BaseAddress;
	unsigned long long AllocationBase;
	unsigned long AllocationProtect;
	unsigned long long RegionSize;
	unsigned long State;
	unsigned long Protect;
	unsigned long Type;
}type;
XCN_NAMESPACE_E(memory)

// --------------------------------------------------------
// 
XCN_NAMESPACE_B(viewer)
typedef enum _tag_viewer_id
{
	DEFAULT_TEXT_VIEWER,
	EVENT_BASE_TEXT_VIEWER,

	TEXT_VIEWER_DASM,

	COMMAND_VIEWER
} id;
XCN_NAMESPACE_E(viewer)

// --------------------------------------------------------
// commone debug event
#define DBG_ATTACH_POINT_EVENT			L"{44392C77-27B4-4179-AAAF-02755295A672}"
#define DBG_PROCESS_RUN_EVENT			L"{8C1AB070-3D33-45A3-82E5-E132CC3170B9}"

typedef enum _tag_break_point_id
{
	NO_BREAK_POINT_ID,

	SUSPEND_BREAK_POINT_ID,
	SOFTWARE_BREAK_POINT_ID,
	HARDWARE_BREAK_POINT_ID
}DebugBreakPointId;

typedef enum _tag_debug_callback_status
{
	DBG_PRE_CALLBACK,
	DBG_POST_CALLBACK
}DebugCallbackStatus;

typedef void(*DebugCallbackT)(DebugCallbackStatus, void *);

// --------------------------------------------------------
//  remote debug event
#define DBG_EXCEPTION_EVENT_NAME	L"{722ED6E2-4F90-425C-9CCB-5E0F06796C33}"
#define DBG_RETURN_EVENT_NAME		L"{BE148B87-DE17-471A-92DA-5F815AFC5905}"
#define DBG_INFO_SHARE_MEMORY_NAME	L"{4254D652-E051-4B55-A958-D8EC8C583A91}"

typedef struct _tag_break_point_type
{
	DebugBreakPointId id;

	unsigned long long ptr;
	unsigned char bytes[16];
}BreakPointType, *BreakPointPtr;

typedef struct _tag_remote_ctx_type
{
	BreakPointType bp[100];
	int count;

	xdv::architecture::x86::context::type context;
	unsigned long error_code;

	int status;
	unsigned long tid;
	unsigned long long last_step;
}DebugContext, *DebugContextPtr;

typedef enum _tag_remote_debuggee_status_id
{
	DEBUGGEE_STATUS_IGNORE,
	DEBUGGEE_STATUS_NEXT_HANDLE,

	DEBUGGEE_STATUS_EXECUTION,
	DEBUGGEE_STATUS_STEP_INTO,
	DEBUGGEE_STATUS_STEP_OVER
}DebuggeeStatusId;

// --------------------------------------------------------
// 
class IObject
{
public:
	virtual xdv::object::id ObjectType() = 0;
	virtual std::string ObjectString() = 0;

	virtual void SetModuleName(std::string module) = 0;
	virtual std::string ModuleName() = 0;
};

class IPlugin : public IObject
{
public:
	virtual std::map<std::string, PluginFunctionType> CallbackFuncs() = 0;
};

class IArchitecture : public IObject
{
public:
	virtual unsigned long long Disassemble(unsigned long long ptr, unsigned char *dump, void *context) = 0;
	virtual unsigned long long Disassemble(unsigned long long ptr, unsigned char *dump, char *mnemonic, size_t output_size) = 0;

	virtual unsigned long long Assemble(unsigned char *dump, size_t *insn_size, char *mnemonic) = 0;
};

typedef void(*ref_callback_type)(unsigned long long callee, unsigned long long caller, void *cb_ctx);
typedef bool(*analyze_callback_type)(unsigned long long ptr, void *cb_ctx, xdv::architecture::x86::block::id id);
class ICodeAnalyzer : public IArchitecture
{
public:
	virtual unsigned long long GetBeforePtr(xdv_handle ih, unsigned long long ptr) = 0;
	virtual unsigned long long GetNextPtr(xdv_handle ih, unsigned long long ptr) = 0;

	virtual void FindReferenceValue(xdv_handle ih, unsigned long long base, size_t size, ref_callback_type cb, void *cb_ctx) = 0;
	virtual xdv::architecture::x86::block::id Analyze(unsigned long long base, unsigned long long end, unsigned long long ptr, unsigned char *dump, std::set<unsigned long long> &ptr_set) = 0;
	virtual xdv::architecture::x86::block::id Analyze(xdv_handle ih, unsigned long long ptr, std::set<unsigned long long> &ptr_set) = 0;
	virtual xdv::architecture::x86::block::id Analyze(xdv_handle ih, unsigned long long ptr, std::vector<unsigned long long> &ptr_vector) = 0;

	virtual unsigned long long Analyze(xdv_handle ih, unsigned long long base, size_t size, analyze_callback_type cb, void *cb_context) = 0;

	virtual bool GetOperandValues(xdv_handle ih, unsigned long long ptr, unsigned char *dump, std::vector<unsigned long long> &v) = 0;

	virtual bool IsJumpCode(unsigned long long ptr, unsigned char *dump, bool *jxx) = 0;
	virtual bool IsCallCode(unsigned long long ptr, unsigned char *dump) = 0;
	virtual bool IsRetCode(unsigned long long ptr, unsigned char *dump) = 0;
	virtual bool IsReadableCode(unsigned long long ptr, unsigned char *dump) = 0;
	virtual bool IsInterruptCode(unsigned long long ptr, unsigned char *dump) = 0;
};

class IParser : public IObject
{
public:
	virtual bool Open(char *path) = 0;

	virtual unsigned long long Read(unsigned long long ptr, unsigned char *out_memory, unsigned long read_size) = 0;
	virtual unsigned long long Write(void * ptr, unsigned char *input_memory, unsigned long write_size) = 0;

	virtual bool Query(unsigned long long ptr, xdv::memory::type *memory_type) = 0;
};

class IDebugger : public IParser
{
public:
	virtual std::map<unsigned long, std::string> ProcessList() = 0;
	virtual unsigned long WaitForProcess(std::string process_name) = 0;

	virtual bool Attach(unsigned long pid) = 0;
	virtual bool Open(unsigned long pid) = 0;
	virtual bool Update() = 0;

	virtual unsigned long ProcessId() = 0;

	virtual void * Alloc(void *ptr, unsigned long size, unsigned long allocation_type, unsigned long protect_type) = 0;

	virtual bool Select(unsigned long tid) = 0;
	virtual void Threads(std::map<unsigned long, unsigned long long> &thread_info_map) = 0;

	virtual bool GetThreadContext(xdv::architecture::x86::context::type *context) = 0;
	virtual bool SetThreadContext(xdv::architecture::x86::context::type *context) = 0;

	virtual std::string Module(unsigned long long ptr) = 0;
	virtual unsigned long Symbol(unsigned long long ptr, unsigned long long *disp, char *symbol_str, unsigned long symbol_size) = 0;
	virtual unsigned long Symbol(unsigned long long ptr, char *symbol_str, unsigned long symbol_size) = 0;
	virtual unsigned long long SymbolToPtr(char *symbol_str) = 0;

	virtual bool StackTrace(xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count) = 0;
	virtual bool StackTraceEx(unsigned long long bp, unsigned long long ip, unsigned long long sp, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count) = 0;

	virtual bool SuspendThread(unsigned long tid) = 0;
	virtual bool ResumeThread(unsigned long tid) = 0;

	virtual unsigned long long GetPebAddress() = 0;
	virtual unsigned long long GetTebAddress() = 0;

	virtual bool StepInto(DebugCallbackT callback, void * cb_ctx) = 0;
	virtual bool StepOver(DebugCallbackT callback, void * cb_ctx) = 0;
	virtual bool RunningProcess() = 0;

	virtual unsigned char * GetBpBackupDump(unsigned long long ptr) = 0;
	virtual DebugBreakPointId GetBreakPointId(unsigned long long ptr) = 0;
	virtual std::vector<unsigned long long> GetBreakPointList() = 0;

	virtual bool SetBreakPoint(DebugBreakPointId id, unsigned long long ptr) = 0;

	virtual bool RestoreBreakPoint(unsigned long long ptr) = 0;
	virtual void ReInstallBreakPoint(unsigned long long ptr) = 0;
	virtual bool DeleteBreakPoint(unsigned long long ptr) = 0;

	virtual void RestoreAllBreakPoint() = 0;
	virtual void ReInstallAllBreakPoint() = 0;
};

class IWorker : public IObject
{
public:
	typedef void(*ThreadRunCallbackType)(IWorker *, void *ctx);

public:
	virtual void Run(xdv_handle viewer_handle, ThreadRunCallbackType callback, void *callback_context) = 0;

	virtual void Print(xdv_handle viewer_handle, std::string str) = 0;
	virtual void Print(xdv_handle viewer_handle, std::string str, bool wait) = 0;
	virtual void PrintAndClear(xdv_handle viewer_handle, std::string str, bool wait) = 0;
	virtual void Clear(xdv_handle viewer_handle) = 0;

	virtual void InsertString(std::string str) = 0;
	virtual void ClearString() = 0;

	virtual void Update() = 0;
	virtual void UpdateAndClear() = 0;

	virtual std::string String() = 0;
	virtual xdv_handle LinkViewerHandle() = 0;

	virtual void Lock() = 0;
	virtual void UnLock() = 0;
};

class IViewer : public IObject
{
public:
	virtual void AddViewer() = 0;
	virtual void CloseViewer() = 0;

	virtual bool IsOpen() = 0;
	virtual bool IsCheckable() = 0;

	virtual bool Update(int status, std::string str) = 0;

	virtual void Print(std::string str) = 0;
	virtual void Print(std::string str, bool wait) = 0;
	virtual void PrintAndClear(std::string str, bool wait = false) = 0;

	virtual IWorker * GetWorker() = 0;
};

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT xvar nullvar();
XDV_WINDOWS_EXPORT xvar ullvar(unsigned long long var);
XDV_WINDOWS_EXPORT xvar ptrvar(void * var);
XDV_WINDOWS_EXPORT xvar handlevar(xdv_handle var);

XDV_WINDOWS_EXPORT unsigned long long ullvar(xvar var);
XDV_WINDOWS_EXPORT void * ptrvar(xvar var);
XDV_WINDOWS_EXPORT xdv_handle handlevar(xvar var);

XDV_WINDOWS_EXPORT unsigned long long ullarg(char * argv[], int argc, char * option);
XDV_WINDOWS_EXPORT void * ptrarg(char * argv[], int argc, char * option);
XDV_WINDOWS_EXPORT xdv_handle handlearg(char * argv[], int argc, char * option);

XDV_WINDOWS_EXPORT bool checkarg(char * argv[], int argc, char * option, char * value);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT bool XdvAddObject(void * object);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT IObject * XdvGetObjectByHandle(xdv_handle h);
XDV_WINDOWS_EXPORT IObject * XdvGetObjectByString(std::string object_str);
XDV_WINDOWS_EXPORT std::vector<IObject *> XdvGetObjectTable();

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT xdv_handle XdvGetHandleByObject(IObject *object);
XDV_WINDOWS_EXPORT xdv_handle XdvGetHandleByString(std::string object_str);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT std::vector<IViewer *> XdvGetViewerTable();

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT xdv_handle XdvGetArchitectureHandle();
XDV_WINDOWS_EXPORT std::vector<IArchitecture *> XdvGetArchitectureTable();

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT xdv_handle XdvGetParserHandle();
XDV_WINDOWS_EXPORT std::vector<IParser *> XdvGetParserTable();

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT std::vector<IDebugger *> XdvGetDebuggerTable();

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT void XdvSetArchitectureHandle(IObject *obj);
XDV_WINDOWS_EXPORT void XdvSetParserHandle(IObject *obj);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT std::map<unsigned long, std::string> XdvProcessList(xdv_handle ih);
XDV_WINDOWS_EXPORT unsigned long XdvWaitForProcess(xdv_handle ih, std::string process_name);
XDV_WINDOWS_EXPORT bool XdvAttachProcess(xdv_handle ih, unsigned long pid);
XDV_WINDOWS_EXPORT bool XdvOpenProcess(xdv_handle ih, unsigned long pid);
XDV_WINDOWS_EXPORT bool XdvUpdateDebuggee(xdv_handle ih);
XDV_WINDOWS_EXPORT unsigned long XdvProcessId(xdv_handle ih);

XDV_WINDOWS_EXPORT bool XdvOpenFile(xdv_handle ih, char *path);

XDV_WINDOWS_EXPORT unsigned long long XdvReadMemory(xdv_handle ih, unsigned long long ptr, unsigned char *out_memory, unsigned long read_size);
XDV_WINDOWS_EXPORT unsigned long long XdvWriteMemory(xdv_handle ih, void * ptr, unsigned char *input_memory, unsigned long write_size);

XDV_WINDOWS_EXPORT bool XdvQueryMemory(xdv_handle ih, unsigned long long ptr, xdv::memory::type *memory_type);
XDV_WINDOWS_EXPORT std::string XdvGetModuleName(xdv_handle ih, unsigned long long ptr);

XDV_WINDOWS_EXPORT bool XdvGetSymbolString(xdv_handle ih, unsigned long long ptr, unsigned long long *disp, char *symbol_str, unsigned long symbol_size);
XDV_WINDOWS_EXPORT bool XdvGetSymbolString(xdv_handle ih, unsigned long long ptr, char *symbol_str, unsigned long symbol_size);
XDV_WINDOWS_EXPORT unsigned long long XdvGetSymbolPointer(xdv_handle ih, char *symbol_str);

XDV_WINDOWS_EXPORT bool XdvSelectThread(xdv_handle ih, unsigned long tid);
XDV_WINDOWS_EXPORT void XdvThreads(xdv_handle ih, std::map<unsigned long, unsigned long long> &thread_info_map);

XDV_WINDOWS_EXPORT bool XdvGetThreadContext(xdv_handle ih, xdv::architecture::x86::context::type *context);
XDV_WINDOWS_EXPORT bool XdvSetThreadContext(xdv_handle ih, xdv::architecture::x86::context::type *context);
XDV_WINDOWS_EXPORT bool XdvStackTrace(xdv_handle ih, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count);
XDV_WINDOWS_EXPORT bool XdvStackTraceEx(xdv_handle ih, unsigned long long bp, unsigned long long sp, unsigned long long ip, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count);

XDV_WINDOWS_EXPORT bool XdvSuspendThread(xdv_handle vh, unsigned long tid);
XDV_WINDOWS_EXPORT bool XdvResumeThread(xdv_handle vh, unsigned long tid);

XDV_WINDOWS_EXPORT void XdvSuspendProcess(xdv_handle ih);
XDV_WINDOWS_EXPORT void XdvResumeProcess(xdv_handle ih);

XDV_WINDOWS_EXPORT unsigned long long XdvGetPebAddress(xdv_handle ih);
XDV_WINDOWS_EXPORT unsigned long long XdvGetTebAddress(xdv_handle ih);

XDV_WINDOWS_EXPORT bool XdvStepInto(xdv_handle ih, DebugCallbackT callback, void * cb_ctx);
XDV_WINDOWS_EXPORT bool XdvStepOver(xdv_handle ih, DebugCallbackT callback, void * cb_ctx);
XDV_WINDOWS_EXPORT bool XdvRunningProcess(xdv_handle ih);

XDV_WINDOWS_EXPORT unsigned char * XdvGetBpBackupDump(xdv_handle ih, unsigned long long ptr);
XDV_WINDOWS_EXPORT bool XdvSetBreakPoint(xdv_handle ih, DebugBreakPointId id, unsigned long long ptr);
XDV_WINDOWS_EXPORT DebugBreakPointId XdvGetBreakPointId(xdv_handle ih, unsigned long long ptr);
XDV_WINDOWS_EXPORT bool XdvRestoreBreakPoint(xdv_handle ih, unsigned long long ptr);
XDV_WINDOWS_EXPORT void XdvReInstallBreakPoint(xdv_handle ih, unsigned long long ptr);
XDV_WINDOWS_EXPORT bool XdvDeleteBreakPoint(xdv_handle ih, unsigned long long ptr);

XDV_WINDOWS_EXPORT void XdvRestoreAllBreakPoint(xdv_handle ih);
XDV_WINDOWS_EXPORT void XdvReInstallAllBreakPoint(xdv_handle ih);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT bool XdvPrintLog(char *format, ...);
XDV_WINDOWS_EXPORT bool XdvPrintViewer(xdv_handle vh, std::string str);
XDV_WINDOWS_EXPORT bool XdvPrintViewer(xdv_handle vh, std::string str, bool wait);
XDV_WINDOWS_EXPORT bool XdvPrintAndClear(xdv_handle vh, std::string str, bool wait);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT bool XdvRun(xdv_handle vh, IWorker::ThreadRunCallbackType callback, void *callback_context);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT unsigned long long XdvGetBeforePtr(xdv_handle ah, xdv_handle ih, unsigned long long ptr);
XDV_WINDOWS_EXPORT unsigned long long XdvGetNextPtr(xdv_handle ah, xdv_handle ih, unsigned long long ptr);

XDV_WINDOWS_EXPORT bool XdvGetOperandValues(xdv_handle ah, xdv_handle ih, unsigned long long ptr, unsigned char *dump, std::vector<unsigned long long> &v);

XDV_WINDOWS_EXPORT unsigned long long XdvDisassemble(xdv_handle ah, unsigned long long ptr, unsigned char *dump, void *context);
XDV_WINDOWS_EXPORT unsigned long long XdvDisassemble(xdv_handle ah, unsigned long long ptr, unsigned char *dump, char *mnemonic, size_t output_size);

XDV_WINDOWS_EXPORT unsigned long long XdvAssemble(xdv_handle ah, unsigned char *dump, size_t *insn_size, char *mnemonic);

XDV_WINDOWS_EXPORT xdv::architecture::x86::block::id XdvAnalyze(xdv_handle ah, xdv_handle ih, unsigned long long ptr, std::set<unsigned long long> &ptr_set);
XDV_WINDOWS_EXPORT xdv::architecture::x86::block::id XdvAnalyze(xdv_handle ah, unsigned long long base, unsigned long long end, unsigned long long ptr, unsigned char *dump, std::set<unsigned long long> &ptr_set);
XDV_WINDOWS_EXPORT xdv::architecture::x86::block::id XdvAnalyze(xdv_handle ah, xdv_handle ih, unsigned long long ptr, std::vector<unsigned long long> &ptr_vector);
XDV_WINDOWS_EXPORT unsigned long long XdvAnalyze(xdv_handle ah, xdv_handle ih, unsigned long long base, size_t size, analyze_callback_type cb, void *cb_context);

XDV_WINDOWS_EXPORT void XdvFineReferenceValues(xdv_handle ah, xdv_handle ih, unsigned long long base, size_t size, ref_callback_type cb, void *cb_ctx);
XDV_WINDOWS_EXPORT unsigned long long XdvFindEntryPoint(xdv_handle ah, xdv_handle ih, unsigned long long ptr);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT bool XdvIsAscii(unsigned char *data, size_t max_len);
XDV_WINDOWS_EXPORT bool XdvIsUnicode(unsigned char *data, size_t max_len);
XDV_WINDOWS_EXPORT bool XdvIsAscii(unsigned char *p, size_t l, std::string &ascii);
XDV_WINDOWS_EXPORT bool XdvIsUnicode(unsigned char *p, size_t l, std::string &ascii);
XDV_WINDOWS_EXPORT bool XdvIsJumpCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump, bool *jxx);
XDV_WINDOWS_EXPORT bool XdvIsCallCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump);
XDV_WINDOWS_EXPORT bool XdvIsRetCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump);
XDV_WINDOWS_EXPORT bool XdvIsReadableCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump);
XDV_WINDOWS_EXPORT bool XdvIsInterruptCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT bool XdvInstallDebugEvent(unsigned long pid);
XDV_WINDOWS_EXPORT void XdvSetDebugEvent();
XDV_WINDOWS_EXPORT void XdvWaitForDebugEvent();

XDV_WINDOWS_EXPORT void * XdvFindPattern(void * base, size_t base_size, unsigned char * code, size_t code_size);

XDV_WINDOWS_EXPORT int XdvInstallRemoteEvent(unsigned long pid);
XDV_WINDOWS_EXPORT void XdvCloseRemoteEvent();

XDV_WINDOWS_EXPORT void XdvExceptionEvent();
XDV_WINDOWS_EXPORT void XdvReturnEvent();
XDV_WINDOWS_EXPORT void * XdvDebugSharedMemory();

XDV_WINDOWS_EXPORT void XdvWaitForExceptionEvent();
XDV_WINDOWS_EXPORT void XdvWaitForReturnEvent();

XDV_WINDOWS_EXPORT bool XdvCheckRemoteEvent();

XDV_WINDOWS_EXPORT bool XdvInjectModule(wchar_t * module_name);

// --------------------------------------------------------
// 
XDV_WINDOWS_EXPORT xvar XdvExe(char *format, ...);
XDV_WINDOWS_EXPORT xvar XdvExeA(char *format, ...);
XDV_WINDOWS_EXPORT xvar XdvExts(char *format, ...);

XDV_WINDOWS_EXPORT std::vector<std::string> XdvSplit(const std::string str, const std::string regex);
XDV_WINDOWS_EXPORT char * XdvValue(char * argv[], int argc, char *option, int *idx);
XDV_WINDOWS_EXPORT unsigned long long XdvToUll(char * ull_str);

XDV_WINDOWS_EXPORT void * XdvLoadModule(char *module_name);

// --------------------------------------------------------
// 
#if 0
template<class T>
XDV_WINDOWS_EXPORT
T * AddInterface()
{
	T *o = new T();
	IObject *object = (IObject *)o;
	if (XdvAddObject(o))
	{
		return o;
	}

	return nullptr;
}
#define __add_object(type_class) AddInterface<type_class>()
#define XENOM_ADD_INTERFACE()			extern "C" XDV_WINDOWS_EXPORT xdv_handle AddInterface()
#endif

#define argof(s)	XdvValue(argv, argc, s, nullptr)
#define hasarg(s, v)	checkarg(argv, argc, s, v)

#define toullarg(s)	ullarg(argv, argc, s)
#define toptrarg(s)	ptrarg(argv, argc, s)
#define tohandlearg(s) handlearg(argv, argc, s)

#endif