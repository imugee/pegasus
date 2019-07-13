#include "x64_arch_exts.h"

#ifdef _WIN64
#pragma comment(lib, "dbgcore_static_x64.lib")
#else
#pragma comment(lib, "dbgcore_static.lib")
#endif

#pragma comment(lib, "corexts.lib")

x64Architecture::x64Architecture()
{
	cs_err ce = cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_);
	if (ce == CS_ERR_OK)
	{
		cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);
		insn_ = cs_malloc(cs_handle_);
	}
	else
	{
		cs_handle_ = 0;
		insn_ = nullptr;
	}

	//
	ks_err ke = ks_open(KS_ARCH_X86, KS_MODE_64, &ks_handle_);
	if (ke)
	{
		ks_handle_ = nullptr;
	}

	arch_type_ = xdv::object::id::XENOM_X64_ANALYZER_OBJECT;
	//mutex_ = CreateMutex(nullptr, FALSE, X86_ARCH_MUTEX_NAME);
}

x64Architecture::~x64Architecture()
{
}

//
//
xdv::object::id x64Architecture::ObjectType()
{
	return arch_type_;
}

std::string x64Architecture::ObjectString()
{
	return "amd64 CPU Architecture";
}

void x64Architecture::SetModuleName(std::string module)
{
}

std::string x64Architecture::ModuleName()
{
	return "";
}

//
// IArchitecture
unsigned long long x64Architecture::Disassemble(unsigned long long ptr, unsigned char *dump, void *context)
{
	mutex_.lock();

	if (cs_handle_ == 0 || insn_ == nullptr)
	{
		mutex_.unlock();

		return 0;
	}

	size_t size = 16;
	if (!cs_disasm_iter(cs_handle_, (const unsigned char **)&dump, &size, &ptr, insn_))
	{
		mutex_.unlock();
		return false;
	}

	xdv::architecture::x86::type_ptr x86_ctx = (xdv::architecture::x86::type_ptr)context;
	x86_ctx->instruction_id = insn_->id;
	x86_ctx->instruction_size = insn_->size;

	cs_x86 *x86 = &(insn_->detail->x86);
	cs_x86_op *op = x86->operands;
	x86_ctx->operand_count = x86->op_count;
	for (int i = 0; i < x86->op_count; ++i)
	{
		cs_x86_op *op = &(x86->operands[i]);
		switch ((int)op->type)
		{
		case X86_OP_IMM:
			x86_ctx->operands[i].id = X86_OP_IMM;
			x86_ctx->operands[i].value = op->imm;
			break;

		case X86_OP_MEM:
			x86_ctx->operands[i].id = X86_OP_MEM;
			x86_ctx->operands[i].value = op->mem.disp;
			break;

		case X86_OP_REG:
			x86_ctx->operands[i].id = X86_OP_REG;
			x86_ctx->operands[i].value = op->reg;
			break;

		default:
			break;
		}
	}

	x86_ctx->instruction_group = 0;
	if (cs_insn_group(cs_handle_, insn_, X86_GRP_JUMP))
	{
		x86_ctx->instruction_group = X86_GRP_JUMP;
	}
	else if (cs_insn_group(cs_handle_, insn_, X86_GRP_CALL))
	{
		x86_ctx->instruction_group = X86_GRP_CALL;
	}
	else if (cs_insn_group(cs_handle_, insn_, X86_GRP_RET))
	{
		x86_ctx->instruction_group = X86_GRP_RET;
	}
	else if (cs_insn_group(cs_handle_, insn_, X86_GRP_INT))
	{
		x86_ctx->instruction_group = X86_GRP_INT;
	}

	mutex_.unlock();

	return x86_ctx->instruction_size;
}

unsigned long long x64Architecture::Disassemble(unsigned long long ptr, unsigned char *dump, char *mnemonic, size_t output_size)
{
	mutex_.lock();

	if (cs_handle_ == 0 || insn_ == nullptr)
	{
		mutex_.unlock();
		return 0;
	}

	size_t size = 16;
	if (!cs_disasm_iter(cs_handle_, (const unsigned char **)&dump, &size, &ptr, insn_))
	{
		mutex_.unlock();
		return 0;
	}

	std::string byte_str;
	for (unsigned int i = 0; i < insn_->size; ++i)
	{
		char c[20] = { 0, };
		sprintf_s(c, sizeof(c), "%02x ", insn_->bytes[i]);
		byte_str += c;
	}

	size_t byte_align = 31;
	size_t byte_str_size = byte_str.size();

	size_t mn_align = 11;
	size_t mn_size = strlen(insn_->mnemonic);

	unsigned char * address_byte = (unsigned char *)&insn_->address;
	unsigned long l_address = *(unsigned long *)address_byte;
	unsigned long h_address = *(unsigned long *)&address_byte[4];

	sprintf_s(mnemonic, output_size, "%08x'%08x	%s%*c %s%*c %s", h_address, l_address, byte_str.c_str()
		, (int)(byte_align - byte_str_size), ' '
		, insn_->mnemonic, (int)(mn_align - mn_size), ' ', insn_->op_str);

	mutex_.unlock();
	return insn_->size;
}

unsigned long long x64Architecture::Assemble(unsigned char *dump, size_t *insn_size, char *mnemonic)
{
	mutex_.lock();

	if (!ks_handle_)
	{
		mutex_.unlock();
		return 0;
	}

	memset(dump, 0, 16);
	*insn_size = 0;

	size_t count = 0;
	unsigned char *encode;
	if (ks_asm(ks_handle_, mnemonic, 0, &encode, insn_size, &count))
	{
		mutex_.unlock();
		return 0;
	}
	memcpy(dump, encode, *insn_size);

	ks_free(encode);
	mutex_.unlock();

	return 1;
}

unsigned long long x64Architecture::GetBeforePtr(xdv_handle ih, unsigned long long ptr, int back_offset)
{
	std::vector<unsigned long long> ptr_vector;
	unsigned long long tmp_ptr = ptr - back_offset;
	do
	{
		unsigned char dump[16] = { 0, };
		unsigned long long readn = XdvReadMemory(ih, tmp_ptr, dump, sizeof(dump));
		if (readn == 0)
		{
			return 0;
		}

		xdv::architecture::x86::type x86;
		unsigned long long size = Disassemble(tmp_ptr, dump, &x86);
		if (size == 0)
		{
			++tmp_ptr;
			continue;
		}

		tmp_ptr += size;
		ptr_vector.push_back(tmp_ptr);
	} while (tmp_ptr < ptr);

	unsigned long long before_ptr = 0;
	for (size_t i = 0; i < ptr_vector.size(); ++i)
	{
		if (ptr_vector[i] == ptr)
		{
			before_ptr = ptr_vector[i - 1];
		}
	}

	return before_ptr;
}

unsigned long long x64Architecture::GetBeforePtr(xdv_handle ih, unsigned long long ptr)
{
	unsigned long long before_ptr = 0;
	int i = 100;
	for (int i = 100; i < 1000; ++i)
	{
		before_ptr = GetBeforePtr(ih, ptr, i++);
		if (before_ptr != 0)
		{
			break;
		}
	}

	return before_ptr;
}

unsigned long long x64Architecture::GetNextPtr(xdv_handle ih, unsigned long long ptr)
{
	unsigned char dump[16] = { 0, };
	unsigned long long readn = XdvReadMemory(ih, ptr, dump, sizeof(dump));
	if (readn == 0)
	{
		return 0;
	}

	xdv::architecture::x86::type x86;
	unsigned long long size = Disassemble(ptr, dump, &x86);
	if (size == 0)
	{
		return 0;
	}

	return ptr + size;
}

bool x64Architecture::check_ptr(xdv_handle ih, unsigned long long ptr)
{
	unsigned long long value = 0;
	unsigned long long r = XdvReadMemory(ih, ptr, (unsigned char *)&value, (unsigned long)sizeof(value));
	if (r == 0)
	{
		unsigned char str[1024] = { 0, };
		unsigned long long readn = XdvReadMemory(ih, ptr, str, sizeof(str));
		if (readn == 0)
		{
			return false;
		}

		std::string ascii;
		std::string unicode;
		if (XdvIsAscii(str, sizeof(str), ascii) ||
			XdvIsUnicode(str, sizeof(str), unicode))
		{
			return true;
		}

		return false;
	}

	return true;
}

void x64Architecture::FindReferenceValue(xdv_handle ih, unsigned long long base, size_t size, ref_callback_type cb, void *cb_ctx)
{
	MessageBox(nullptr, L"64", L"", MB_OK);
	unsigned char *dump = (unsigned char *)malloc(size);
	if (!dump)
	{
		return;
	}
	std::shared_ptr<void> dump_closer(dump, free);
	memset(dump, 0, size);

	unsigned long long readn = XdvReadMemory(ih, base, dump, (unsigned long)size);
	if (readn == 0)
	{
		return;
	}

	unsigned long long end = base + size;
	unsigned long long ptr = base;
	do
	{
		unsigned long long offset = ptr - base;
		xdv::architecture::x86::type x86_ctx;
		if (!Disassemble(ptr, &dump[offset], (void *)&x86_ctx))
		{
			++ptr;
			if (ptr > end)
			{
				break;
			}

			continue;
		}

		unsigned long long x64_disp = 0;
		unsigned long long value = 0;
		size_t value_size = sizeof(value);
		unsigned long long r = 0;
		for (unsigned long i = 0; i < x86_ctx.operand_count; ++i)
		{
			switch (x86_ctx.operands[i].id)
			{
			case xdv::architecture::x86::operand::id::X86_OP_IMM:
				if (check_ptr(ih, x86_ctx.operands[i].value) && cb)
				{
					cb(x86_ctx.operands[i].value, ptr, cb_ctx);
				}

				break;

			case xdv::architecture::x86::operand::id::X86_OP_MEM:
				value = 0;
				value_size = sizeof(value);
				x64_disp = ptr + x86_ctx.operands[i].value + x86_ctx.instruction_size;
				r = XdvReadMemory(ih, x64_disp, (unsigned char *)&value, (unsigned long)value_size);
				if (r != 0)
				{
					if (check_ptr(ih, value) && cb)
					{
						cb(value, ptr, cb_ctx);
					}
					else if (check_ptr(ih, x64_disp) && cb)
					{
						cb(x64_disp, ptr, cb_ctx);
					}

				}
				break;

			default:
				break;
			}
		}

		ptr += x86_ctx.instruction_size;
	} while (ptr < end);
}

bool x64Architecture::check(unsigned long long ptr, unsigned long long base, unsigned long long end)
{
	if (base <= ptr && end >= ptr)
	{
		return true;
	}

	return false;
}

xdv::architecture::x86::block::id x64Architecture::Analyze(unsigned long long base, unsigned long long end, unsigned long long ptr, unsigned char *dump, std::set<unsigned long long> &ptr_set)
{
	if (!dump)
	{
		return xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
	}

	xdv::architecture::x86::block::id id = xdv::architecture::x86::block::id::X86_UNKNOWN_BLOCK;
	std::list<unsigned long long> stack;
	std::list<unsigned long long>::iterator bit;

	unsigned long long end_ptr = 0;
	unsigned long long end_offset = 0;
	while (ptr && check(ptr, base, end))
	{
		std::list<unsigned long long>::iterator stack_it = stack.begin();

		unsigned long long offset = ptr - base;
		xdv::architecture::x86::type x86_ctx;
		if (!Disassemble(ptr, &dump[offset], (void *)&x86_ctx))
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
				break;
			}
		}

		bool is_jmp = false;
		if (x86_ctx.instruction_group == X86_GRP_JUMP)
		{
			is_jmp = true;
		}

		std::set<unsigned long long>::iterator vit = ptr_set.find(ptr);
		if (vit != ptr_set.end())
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
				break;
			}
		}

		ptr_set.insert(std::set<unsigned long long>::value_type(ptr));
		end_ptr = ptr;

		if (is_jmp && x86_ctx.instruction_id != X86_INS_JMP)
		{
			stack.push_back(ptr + x86_ctx.instruction_size);
			if (x86_ctx.operands[0].id != X86_OP_IMM)
			{
				if (stack.size())
				{
					bit = stack.end();
					ptr = *(--bit);
					stack.pop_back();

					continue;
				}
				else
				{
					id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
					break;
				}
			}

			ptr = x86_ctx.operands[0].value;
			continue;
		}

		if (x86_ctx.instruction_id == X86_INS_JMP)
		{
			if (x86_ctx.operands[0].id != X86_OP_IMM)
			{
				if (stack.size())
				{
					bit = stack.end();
					ptr = *(--bit);
					stack.pop_back();

					continue;
				}
				else
				{
					id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
					break;
				}
			}

			ptr = x86_ctx.operands[0].value;
			if (!check(ptr, base, end) && stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();
			}
		}
		else if (x86_ctx.instruction_group == X86_GRP_RET)
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
				break;
			}
		}
		else if (x86_ctx.instruction_group != X86_GRP_INT && !(dump[offset] == 0 && dump[offset + 1] == 0))
		{
			ptr += x86_ctx.instruction_size;
		}
		else
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_DEBUG_TRAP;
				break;
			}
		}
	}

	return id;
}

xdv::architecture::x86::block::id x64Architecture::Analyze(xdv_handle ih, unsigned long long ptr, std::set<unsigned long long> &ptr_set)
{
	unsigned long long backup = ptr;
	xdv::architecture::x86::block::id id = xdv::architecture::x86::block::id::X86_UNKNOWN_BLOCK;
	std::list<unsigned long long> stack;
	std::list<unsigned long long>::iterator bit;

	unsigned long long end_ptr = 0;
	unsigned long long end_offset = 0;
	while (ptr)
	{
		std::list<unsigned long long>::iterator stack_it = stack.begin();

		unsigned char dump[16] = { 0, };
		unsigned long long read = XdvReadMemory(ih, ptr, dump, sizeof(dump));
		if (read == 0)
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
				break;
			}
		}

		xdv::architecture::x86::type x86_ctx;
		if (!Disassemble(ptr, dump, (void *)&x86_ctx))
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
				break;
			}
		}

		bool is_jmp = false;
		if (x86_ctx.instruction_group == X86_GRP_JUMP)
		{
			is_jmp = true;
		}

		std::set<unsigned long long>::iterator vit = ptr_set.find(ptr);
		if (vit != ptr_set.end())
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
				break;
			}
		}

		ptr_set.insert(std::set<unsigned long long>::value_type(ptr));
		end_ptr = ptr;

		if (is_jmp && x86_ctx.instruction_id != X86_INS_JMP)
		{
			stack.push_back(ptr + x86_ctx.instruction_size);
			if (x86_ctx.operands[0].id != X86_OP_IMM)
			{
				if (stack.size())
				{
					bit = stack.end();
					ptr = *(--bit);
					stack.pop_back();

					continue;
				}
				else
				{
					id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
					break;
				}
			}

			ptr = x86_ctx.operands[0].value;
			continue;
		}

		if (x86_ctx.instruction_id == X86_INS_JMP)
		{
			if (x86_ctx.operands[0].id != X86_OP_IMM)
			{
				if (stack.size())
				{
					bit = stack.end();
					ptr = *(--bit);
					stack.pop_back();

					continue;
				}
				else
				{
					id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
					break;
				}
			}

			ptr = x86_ctx.operands[0].value;
		}
		else if (x86_ctx.instruction_group == X86_GRP_RET)
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
				break;
			}
		}
		else if (x86_ctx.instruction_group != X86_GRP_INT && !(dump[0] == 0 && dump[1] == 0))
		{
			ptr += x86_ctx.instruction_size;
		}
		else
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_DEBUG_TRAP;
				break;
			}
		}
	}

	return id;
}

xdv::architecture::x86::block::id x64Architecture::Analyze(xdv_handle ih, unsigned long long ptr, std::vector<unsigned long long> &ptr_vector)
{
	std::set<unsigned long long> ptr_set;
	unsigned long long backup = ptr;
	xdv::architecture::x86::block::id id = xdv::architecture::x86::block::id::X86_UNKNOWN_BLOCK;
	std::list<unsigned long long> stack;
	std::list<unsigned long long>::iterator bit;

	unsigned long long end_ptr = 0;
	unsigned long long end_offset = 0;
	while (ptr)
	{
		std::list<unsigned long long>::iterator stack_it = stack.begin();

		unsigned char dump[16] = { 0, };
		unsigned long long read = XdvReadMemory(ih, ptr, dump, sizeof(dump));
		if (read == 0)
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
				break;
			}
		}

		xdv::architecture::x86::type x86_ctx;
		if (!Disassemble(ptr, dump, (void *)&x86_ctx))
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
				break;
			}
		}

		bool is_jmp = false;
		if (x86_ctx.instruction_group == X86_GRP_JUMP)
		{
			is_jmp = true;
		}

		std::set<unsigned long long>::iterator vit = ptr_set.find(ptr);
		if (vit != ptr_set.end())
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();

				continue;
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
				break;
			}
		}

		ptr_set.insert(std::set<unsigned long long>::value_type(ptr));
		ptr_vector.push_back(ptr);
		end_ptr = ptr;

		if (is_jmp && x86_ctx.instruction_id != X86_INS_JMP)
		{
			stack.push_back(ptr + x86_ctx.instruction_size);
			if (x86_ctx.operands[0].id != X86_OP_IMM)
			{
				if (stack.size())
				{
					bit = stack.end();
					ptr = *(--bit);
					stack.pop_back();

					continue;
				}
				else
				{
					id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
					break;
				}
			}

			ptr = x86_ctx.operands[0].value;
			continue;
		}

		if (x86_ctx.instruction_id == X86_INS_JMP)
		{
			if (x86_ctx.operands[0].id != X86_OP_IMM)
			{
				if (stack.size())
				{
					bit = stack.end();
					ptr = *(--bit);
					stack.pop_back();

					continue;
				}
				else
				{
					id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
					break;
				}
			}

			ptr = x86_ctx.operands[0].value;
		}
		else if (x86_ctx.instruction_group == X86_GRP_RET)
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_CODE_BLOCK;
				break;
			}
		}
		else if (x86_ctx.instruction_group != X86_GRP_INT && !(dump[0] == 0 && dump[1] == 0))
		{
			ptr += x86_ctx.instruction_size;
		}
		else
		{
			if (stack.size())
			{
				bit = stack.end();
				ptr = *(--bit);
				stack.pop_back();
			}
			else
			{
				id = xdv::architecture::x86::block::id::X86_DEBUG_TRAP;
				break;
			}
		}
	}

	return id;
}

unsigned long long x64Architecture::Analyze(xdv_handle ih, unsigned long long base, size_t size, analyze_callback_type cb, void *cb_context)
{
	unsigned char *dump = (unsigned char *)malloc(size);
	if (!dump)
	{
		return 0;
	}
	std::shared_ptr<void> dump_closer(dump, free);
	memset(dump, 0, size);

	unsigned long long readn = XdvReadMemory(ih, base, dump, (unsigned long)size);
	if (readn == 0)
	{
		return 0;
	}

	unsigned long long end = base + size;
	unsigned long long ptr = base;
	std::set<unsigned long long> visit;
	do
	{
		unsigned long long offset = ptr - base;
		xdv::architecture::x86::type x86_ctx;
		if (!Disassemble(ptr, &dump[offset], &x86_ctx))
		{
			++ptr;
			if (ptr > end)
			{
				break;
			}
			continue;
		}

		bool is_nop = (x86_ctx.instruction_id == X86_INS_NOP);
		bool is_int = (x86_ctx.instruction_id == X86_INS_INT3);
		bool is_add = (x86_ctx.instruction_id == X86_INS_ADD);

		if ((is_nop || is_int || is_add))
		{
			ptr += x86_ctx.instruction_size;
			if (ptr > end)
			{
				break;
			}

			continue;
		}

		std::set<unsigned long long>::iterator mit = visit.find(ptr);
		if (mit != visit.end())
		{
			ptr += x86_ctx.instruction_size;
			if (ptr > end)
			{
				break;
			}

			continue;
		}

		size_t insn_size = x86_ctx.instruction_size;
		xdv::architecture::x86::block::id id = Analyze(ih, ptr, visit);

		if (cb)
		{
			if (!cb(ptr, cb_context, id))
			{
				break;
			}
		}

		ptr += insn_size;
	} while (ptr <= end);

	{
		unsigned long long offset = ptr - base;
		xdv::architecture::x86::type x86_ctx;
		if (!Disassemble(ptr, &dump[offset], &x86_ctx))
		{
			++ptr;
		}
		else
		{
			ptr += x86_ctx.instruction_size;
		}
	}

	return ptr;
}

bool x64Architecture::GetOperandValues(xdv_handle ih, unsigned long long ptr, unsigned char *dump, std::vector<unsigned long long> &v)
{
	xdv::architecture::x86::type x86_ctx_type;
	unsigned long long dt = Disassemble(ptr, dump, &x86_ctx_type);
	if (!dt)
	{
		return false;
	}

	v.clear();
	for (unsigned long i = 0; i < x86_ctx_type.operand_count; ++i)
	{
		if (x86_ctx_type.operands[i].id == xdv::architecture::x86::operand::id::X86_OP_MEM)
		{
			unsigned long long value = 0;
			unsigned long value_size = sizeof(value);
			unsigned long long x64_disp = ptr + x86_ctx_type.operands[i].value + x86_ctx_type.instruction_size;
			unsigned long long r = XdvReadMemory(ih, x64_disp, (unsigned char *)&value, (unsigned long)value_size);
			if (r != 0)
			{
				unsigned long long tmp = 0;
				if (XdvReadMemory(ih, value, (unsigned char *)&tmp, sizeof(unsigned long long)))
				{
					v.push_back(value);
				}
				else
				{
					unsigned long long tmp = 0;
					if (XdvReadMemory(ih, x64_disp, (unsigned char *)&tmp, sizeof(unsigned long long)))
					{
						v.push_back(x64_disp);
					}
				}
			}
		}
		else if (x86_ctx_type.operands[i].id == xdv::architecture::x86::operand::id::X86_OP_IMM)
		{
			v.push_back(x86_ctx_type.operands[i].value);
		}
	}

	switch (x86_ctx_type.instruction_id)
	{
	case X86_INS_CALL:
	case X86_INS_JMP:
		return true;
	}

	return false;
}

bool x64Architecture::IsJumpCode(unsigned long long ptr, unsigned char *dump, bool *jxx)
{
	xdv::architecture::x86::type x86_ctx_type;
	unsigned long long dt = Disassemble(ptr, dump, &x86_ctx_type);
	if (!dt)
	{
		return false;
	}

	bool r = false;
	if (x86_ctx_type.instruction_group == X86_GRP_JUMP)
	{
		r = true;
		if (jxx)
		{
			if (x86_ctx_type.instruction_id != X86_INS_JMP)
			{
				*jxx = true;
			}
		}
	}

	return r;
}

bool x64Architecture::IsCallCode(unsigned long long ptr, unsigned char *dump)
{
	xdv::architecture::x86::type x86_ctx_type;
	unsigned long long dt = Disassemble(ptr, dump, &x86_ctx_type);
	if (!dt)
	{
		return false;
	}

	if (x86_ctx_type.instruction_group == X86_GRP_CALL)
	{
		return true;
	}

	return false;
}

bool x64Architecture::IsRetCode(unsigned long long ptr, unsigned char *dump)
{
	xdv::architecture::x86::type x86_ctx_type;
	unsigned long long dt = Disassemble(ptr, dump, &x86_ctx_type);
	if (!dt)
	{
		return false;
	}

	bool r = false;
	if (x86_ctx_type.instruction_group == X86_GRP_RET)
	{
		r = true;
	}

	return r;
}

bool x64Architecture::IsReadableCode(unsigned long long ptr, unsigned char *dump)
{
	xdv::architecture::x86::type x86_ctx_type;
	unsigned long long dt = Disassemble(ptr, dump, &x86_ctx_type);
	if (!dt)
	{
		return false;
	}

	bool r = false;
	if (x86_ctx_type.instruction_id == X86_INS_PUSH
		|| x86_ctx_type.instruction_id == X86_INS_MOV
		|| x86_ctx_type.instruction_id == X86_INS_LEA)
	{
		r = true;
	}

	return r;
}

bool x64Architecture::IsInterruptCode(unsigned long long ptr, unsigned char *dump)
{
	xdv::architecture::x86::type x86_ctx_type;
	unsigned long long dt = Disassemble(ptr, dump, &x86_ctx_type);
	if (!dt)
	{
		return false;
	}

	bool r = false;
	if (x86_ctx_type.instruction_group == X86_GRP_INT)
	{
		r = true;
	}

	return r;
}

// 
#ifdef DLL_VERSION
XENOM_ADD_INTERFACE()
{
	IObject * obj = __add_object(x64Architecture);
	if (obj)
	{
		return XdvGetHandleByObject(obj);
	}

	return 0;
}
#endif