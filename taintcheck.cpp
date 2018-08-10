#include "pin.H"
#include <map>
#include <list>
#include <algorithm>

#define MAIN "main"
#define FILENO "fileno"

// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"

typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;

map<ADDRINT, int> taintmap; // track tainted memory

void printmap() {
		printf("Current tainted memory spaces:\n");
		if(taintmap.size() == 0) {
				printf("\tNone\n");
				return;
		}
		ADDRINT start, last;
		map<ADDRINT, int>::iterator it = taintmap.begin();
		start = last = it->first;
		it++;
		for(; it != taintmap.end(); it++) {
				if(it->first == last + 1) last = it->first;
				else {
						printf("\t0x%08x - 0x%08x\n", start, last);
						start = last = it->first;
				}
		}
		printf("\t0x%08x - 0x%08x\n", start, last);
}

bool isTainted(ADDRINT addr) {
		if(taintmap.find(addr) == taintmap.end()) return false;
		else return true;
}

void insertmem(ADDRINT addr) {
		taintmap.insert(pair<ADDRINT, int>(addr, 0));
}

void clearmem(ADDRINT addr) {
		taintmap.erase(addr);
}

INT32 Usage()
{
		return -1;
}

int countBytes(char* ptr) {
		int count = 0;
		while(*ptr != '\0') {
				count++;
				ptr++;
		}
		return count;
}

bool isStdin(FILE *fd)
{
		int ret = org_fileno(fd);
		if(ret == 0) return true;
		return false;
}

bool fgets_stdin = false;
int fgets_size = 0;
VOID fgetsTail(char* ret)
{
		if(fgets_stdin && ret != NULL) {
				int count = 0;
				while(*(ret + count) != '\0' && count < fgets_size) count++;
				for(int i = 0; i < count; i++) {
						insertmem((ADDRINT)ret + i);
				}
				printf("fgetsTail: ret %p, size %d\n", ret, count);
				printmap();
		}
		fgets_stdin = false;
		fgets_size = 0;
}

VOID fgetsHead(char* dest, int size, FILE *stream)
{
		if(isStdin(stream)) {
				printf("fgetsHead: dest %p, size %d, stream: stdin\n", dest, size);
				fgets_stdin = true;
				fgets_size = size;
		} 
}

VOID getsTail(char* ret) {
		int count = 0;
		while(*(ret + count) != '\0') count++;
		for(int i = 0; i < count; i++) {
				insertmem((ADDRINT)(ret + i));
		}
		printf("getsTail: ret %p, size %d\n", ret, count);
		printmap();
}

VOID getsHead(char* dest) {
		printf("getsHead: dest %p\n", dest);
}

VOID mainHead(int argc, char* argv[]) {
		printf("mainHead: ");
		if(argc < 2) {
				printf("No command line args\n");
				return;
		}
		int size;
		for(int i = 1; i < argc; i++) {
				size = countBytes(argv[i]);	
				for(int j = 0; j < size; j++) {
						insertmem((ADDRINT)(argv[i] + j));
				}
				if(i != 1) printf(" | ");
				printf("argv[%d] %p, size %d", i, argv[i], size);
		}
		printf("\n");
		printmap();
}

VOID strcpyHead(char* dest, char* src) {
		int size = countBytes(src);
		ADDRINT d, s;
		bool change = false;
		for(int i = 0; i < size; i++) {
				d = (ADDRINT)(dest + i);
				s = (ADDRINT)(src + i);
				if(isTainted(s)) {
						insertmem(d);
						change = true;
				}
				else if(isTainted(d)) {
						clearmem(d);
						change = true;
				}
		}
		if(change) {
				printf("strcpyHead: dest %p, src %p, size %d\n", dest, src, size);
				printmap();
		}
}

VOID strncpyHead(char* dest, char* src, int size) {
		int count = countBytes(src);
		ADDRINT d, s;
		bool change = false;
		for(int i = 0; i < count; i++) {
				d = (ADDRINT)(dest + i);
				s = (ADDRINT)(src + i);
				if(isTainted(s)) {
						insertmem(d);
						change = true;
				}
				else if(isTainted(d)) {
						clearmem(d);
						change = true;
				}
		}
		if(count < size) {
				for(int j = count; j < size; j++) {
						d = (ADDRINT)(dest + j);
						if(isTainted(d)) clearmem(d);
				}
		}
		if(change) {
				printf("strcpyHead: dest %p, src %p, size %d\n", dest, src, size);
				printmap();
		}
}

VOID strcatHead(char* dest, char* src) {
		int ssize = countBytes(src);
		int dsize = countBytes(dest);
		ADDRINT d, s;
		bool change = false;
		for(int i = 0; i < ssize; i++) {
				d = (ADDRINT)(dest + dsize + i);
				s = (ADDRINT)(src + i);
				if(isTainted(s)) {
						insertmem(d);
						change = true;
				}
				else if(isTainted(d)) {
						clearmem(d);
						change = true;
				}
		}
		if(change) {
				printf("strcatHead: catdest %p, src %p, size %d\n", dest + dsize, src, ssize);
				printmap();
		}
}

VOID strncatHead(char* dest, char* src, int size) {
		int ssize = countBytes(src);
		int dsize = countBytes(dest);
		ADDRINT d, s;
		bool change = false;
		int bound = (size > ssize ? ssize : size);
		for(int i = 0; i < bound; i++) {
				d = (ADDRINT)(dest + dsize + i);
				s = (ADDRINT)(src + i);
				if(isTainted(s)) {
						insertmem(d);
						change = true;
				}
				else if(isTainted(d)) {
						clearmem(d);
						change = true;
				}
		}
		if(change) {
				printf("strncatHead: catdest %p, src %p, size %d\n", dest + dsize, src, size);
				printmap();
		}
}

VOID memcpyHead(void* dest, void* src, int size) {
		ADDRINT d, s;
		bool change = false;
		for(int i = 0; i < size; i++) {
				d = (ADDRINT)dest + i;
				s = (ADDRINT)src + i;
				if(isTainted(s)) {
						insertmem(d);
						change = true;
				}
				else if(isTainted(d)) {
						clearmem(d);
						change = true;
				}
		}
		if(change) {
			printf("strcpyHead: dest %p, src %p, size %d\n", dest, src, size);
			printmap();
		}
}

VOID bzeroHead(void* dest, int size) {
		ADDRINT d;
		bool change = false;
		for(int i = 0; i < size; i++) {
				d = (ADDRINT)((char*)dest + i);
				if(isTainted(d)) {
						clearmem(d);
						change = true;
				}
		}
		if(change) {
				printf("bzeroHead: dest %p, size %d\n", dest, size);
				printmap();
		}
}

VOID memsetHead(void* dest, int size) {
		ADDRINT d;
		bool change = false;
		for(int i = 0; i < size; i++) {
				d = (ADDRINT)((char*)dest + i);
				if(isTainted(d)) {
						clearmem(d);
						change = true;
				}
		}
		if(change) {
				printf("memsetHead: dest %p, size %d\n", dest, size);
				printmap();
		}
}

VOID indirectBranch(ADDRINT insAddr, ADDRINT readAddr, ADDRINT target) {
		if(isTainted(readAddr)) {
				printf("****************Attack detected!****************\n");
				printf("IndirectBranch(0x%08x): jump to 0x%08x, stored in tainted byte(0x%08x)\n", insAddr, target, readAddr);
				printf("************************************************\n");
				exit(0);
		}
}

VOID Instruction(INS ins, VOID *v)
{
		if(INS_IsIndirectBranchOrCall(ins)) {
				if(INS_IsMemoryRead(ins)) {
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)indirectBranch,
								IARG_INST_PTR,
								IARG_MEMORYREAD_EA,
								IARG_BRANCH_TARGET_ADDR,
								IARG_END);
				}	
		}
}

VOID Image(IMG img, VOID *v) {
		RTN rtn;	

		// taint check
		rtn = RTN_FindByName(img, FGETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);

				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, FILENO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				AFUNPTR fptr = RTN_Funptr(rtn);
				org_fileno = (FP_FILENO)(fptr);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, GETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getsHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
								IARG_END);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail, 
								IARG_FUNCRET_EXITPOINT_VALUE, 
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MAIN);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}

		// propagation
		rtn = RTN_FindByName(img, STRCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRNCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRCAT);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRNCAT);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MEMCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_Close(rtn);
		}

		// reset
		rtn = RTN_FindByName(img, BZERO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MEMSET);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memsetHead,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_Close(rtn);
		}
}

int main(int argc, char *argv[])
{
  PIN_InitSymbols();

		if(PIN_Init(argc, argv)){
				return Usage();
		}
		
  		IMG_AddInstrumentFunction(Image, 0);
		INS_AddInstrumentFunction(Instruction, 0);
		PIN_StartProgram();

		return 0;
}

